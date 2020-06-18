package khipu;

import java.util.function.BiFunction;
import org.hyperledger.besu.ethereum.ProtocolContext;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.chain.GenesisState;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.storage.StorageProvider;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;
import org.hyperledger.besu.plugin.services.MetricsSystem;

public interface ProtocolContextFactory {
  ProtocolContext create(
      final StorageProvider storageProvider,
      final GenesisState genesisState,
      final ProtocolSchedule protocolSchedule,
      final MetricsSystem metricsSystem,
      final BiFunction<Blockchain, WorldStateArchive, Object> consensusContextFactory);
}
