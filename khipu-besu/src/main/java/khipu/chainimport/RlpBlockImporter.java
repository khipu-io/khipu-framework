package khipu.chainimport;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.apache.logging.log4j.LogManager.getLogger;

import com.google.common.base.MoreObjects;
import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import khipu.controller.BesuController;
import org.apache.logging.log4j.Logger;
import org.hyperledger.besu.ethereum.ProtocolContext;
import org.hyperledger.besu.ethereum.chain.MutableBlockchain;
import org.hyperledger.besu.ethereum.core.Block;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.BlockImporter;
import org.hyperledger.besu.ethereum.core.Difficulty;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.mainnet.BlockHeaderValidator;
import org.hyperledger.besu.ethereum.mainnet.HeaderValidationMode;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.ethereum.mainnet.ScheduleBasedBlockHeaderFunctions;
import org.hyperledger.besu.ethereum.util.RawBlockIterator;

/** Tool for importing rlp-encoded block data from files. */
public class RlpBlockImporter implements Closeable {
  private static final Logger LOG = getLogger();

  private final Semaphore blockBacklog = new Semaphore(2);

  private final ExecutorService validationExecutor = Executors.newCachedThreadPool();
  private final ExecutorService importExecutor = Executors.newSingleThreadExecutor();

  /**
   * Imports blocks that are stored as concatenated RLP sections in the given file into Besu's block
   * storage.
   *
   * @param blocks Path to the file containing the blocks
   * @param besuController the BesuController that defines blockchain behavior
   * @param skipPowValidation Skip proof of work validation (correct mix hash and difficulty)
   * @return the import result
   * @throws IOException On Failure
   */
  public RlpBlockImporter.ImportResult importBlockchain(
      final Path blocks, final BesuController besuController, final boolean skipPowValidation)
      throws IOException {
    return importBlockchain(blocks, besuController, skipPowValidation, 0L, Long.MAX_VALUE);
  }

  public RlpBlockImporter.ImportResult importBlockchain(
      final Path blocks,
      final BesuController besuController,
      final boolean skipPowValidation,
      final long startBlock,
      final long endBlock)
      throws IOException {
    final ProtocolSchedule protocolSchedule = besuController.getProtocolSchedule();
    final ProtocolContext context = besuController.getProtocolContext();
    final MutableBlockchain blockchain = context.getBlockchain();
    int count = 0;

    try (final RawBlockIterator iterator =
        new RawBlockIterator(
            blocks,
            rlp ->
                BlockHeader.readFrom(
                    rlp, ScheduleBasedBlockHeaderFunctions.create(protocolSchedule)))) {
      BlockHeader previousHeader = null;
      CompletableFuture<Void> previousBlockFuture = null;
      while (iterator.hasNext()) {
        final Block block = iterator.next();
        final BlockHeader header = block.getHeader();
        final long blockNumber = header.getNumber();
        if (blockNumber == BlockHeader.GENESIS_BLOCK_NUMBER
            || blockNumber < startBlock
            || blockNumber >= endBlock) {
          continue;
        }
        if (blockNumber % 100 == 0) {
          LOG.info("Import at block {}", blockNumber);
        }
        if (blockchain.contains(header.getHash())) {
          continue;
        }
        if (previousHeader == null) {
          previousHeader = lookupPreviousHeader(blockchain, header);
        }
        final ProtocolSpec protocolSpec = protocolSchedule.getByBlockNumber(blockNumber);
        final BlockHeader lastHeader = previousHeader;

        final CompletableFuture<Void> validationFuture =
            CompletableFuture.runAsync(
                () -> validateBlock(protocolSpec, context, lastHeader, header, skipPowValidation),
                validationExecutor);

        final CompletableFuture<Void> extractingFuture =
            CompletableFuture.runAsync(() -> extractSignatures(block));

        final CompletableFuture<Void> calculationFutures;
        if (previousBlockFuture == null) {
          calculationFutures = extractingFuture;
        } else {
          calculationFutures = CompletableFuture.allOf(extractingFuture, previousBlockFuture);
        }

        try {
          blockBacklog.acquire();
        } catch (final InterruptedException e) {
          LOG.error("Interrupted adding to backlog.", e);
          break;
        }
        previousBlockFuture =
            validationFuture.runAfterBothAsync(
                calculationFutures,
                () -> evaluateBlock(context, block, header, protocolSpec, skipPowValidation),
                importExecutor);

        ++count;
        previousHeader = header;
      }
      if (previousBlockFuture != null) {
        previousBlockFuture.join();
      }
      return new RlpBlockImporter.ImportResult(
          blockchain.getChainHead().getTotalDifficulty(), count);
    }
  }

  private void extractSignatures(final Block block) {
    final List<CompletableFuture<Void>> futures =
        new ArrayList<>(block.getBody().getTransactions().size());
    for (final Transaction tx : block.getBody().getTransactions()) {
      futures.add(CompletableFuture.runAsync(tx::getSender, validationExecutor));
    }
    for (final CompletableFuture<Void> future : futures) {
      future.join();
    }
  }

  private void validateBlock(
      final ProtocolSpec protocolSpec,
      final ProtocolContext context,
      final BlockHeader previousHeader,
      final BlockHeader header,
      final boolean skipPowValidation) {
    final BlockHeaderValidator blockHeaderValidator = protocolSpec.getBlockHeaderValidator();
    final boolean validHeader =
        blockHeaderValidator.validateHeader(
            header,
            previousHeader,
            context,
            skipPowValidation
                ? HeaderValidationMode.LIGHT_DETACHED_ONLY
                : HeaderValidationMode.DETACHED_ONLY);
    if (!validHeader) {
      throw new IllegalStateException("Invalid header at block number " + header.getNumber() + ".");
    }
  }

  private void evaluateBlock(
      final ProtocolContext context,
      final Block block,
      final BlockHeader header,
      final ProtocolSpec protocolSpec,
      final boolean skipPowValidation) {
    try {
      final BlockImporter blockImporter = protocolSpec.getBlockImporter();
      final boolean blockImported =
          blockImporter.importBlock(
              context,
              block,
              skipPowValidation
                  ? HeaderValidationMode.LIGHT_SKIP_DETACHED
                  : HeaderValidationMode.SKIP_DETACHED,
              skipPowValidation ? HeaderValidationMode.LIGHT : HeaderValidationMode.FULL);
      if (!blockImported) {
        throw new IllegalStateException(
            "Invalid block at block number " + header.getNumber() + ".");
      }
    } finally {
      blockBacklog.release();
    }
  }

  private BlockHeader lookupPreviousHeader(
      final MutableBlockchain blockchain, final BlockHeader header) {
    return blockchain
        .getBlockHeader(header.getParentHash())
        .orElseThrow(
            () ->
                new IllegalStateException(
                    String.format(
                        "Block %s does not connect to the existing chain. Current chain head %s",
                        header.getNumber(), blockchain.getChainHeadBlockNumber())));
  }

  @Override
  public void close() {
    validationExecutor.shutdownNow();
    try {
      validationExecutor.awaitTermination(5, SECONDS);
    } catch (final Exception e) {
      LOG.error("Error shutting down validatorExecutor.", e);
    }

    importExecutor.shutdownNow();
    try {
      importExecutor.awaitTermination(5, SECONDS);
    } catch (final Exception e) {
      LOG.error("Error shutting down importExecutor", e);
    }
  }

  public static final class ImportResult {

    public final Difficulty td;

    final int count;

    ImportResult(final Difficulty td, final int count) {
      this.td = td;
      this.count = count;
    }

    @Override
    public String toString() {
      return MoreObjects.toStringHelper(this).add("td", td).add("count", count).toString();
    }
  }
}
