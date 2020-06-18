package khipu.controller;

import org.hyperledger.besu.controller.NoopPluginServiceFactory;
import org.hyperledger.besu.controller.PluginServiceFactory;
import org.hyperledger.besu.ethereum.ProtocolContext;
import org.hyperledger.besu.ethereum.blockcreation.DefaultBlockScheduler;
import org.hyperledger.besu.ethereum.blockcreation.EthHashMinerExecutor;
import org.hyperledger.besu.ethereum.blockcreation.EthHashMiningCoordinator;
import org.hyperledger.besu.ethereum.blockcreation.MiningCoordinator;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.MiningParameters;
import org.hyperledger.besu.ethereum.eth.manager.EthProtocolManager;
import org.hyperledger.besu.ethereum.eth.sync.state.SyncState;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPool;
import org.hyperledger.besu.ethereum.mainnet.MainnetBlockHeaderValidator;
import org.hyperledger.besu.ethereum.mainnet.MainnetProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

public class MainnetBesuControllerBuilder extends BesuControllerBuilder {

  @Override
  protected MiningCoordinator createMiningCoordinator(
      final ProtocolSchedule protocolSchedule,
      final ProtocolContext protocolContext,
      final TransactionPool transactionPool,
      final MiningParameters miningParameters,
      final SyncState syncState,
      final EthProtocolManager ethProtocolManager) {
    final EthHashMinerExecutor executor =
        new EthHashMinerExecutor(
            protocolContext,
            protocolSchedule,
            transactionPool.getPendingTransactions(),
            miningParameters,
            new DefaultBlockScheduler(
                MainnetBlockHeaderValidator.MINIMUM_SECONDS_SINCE_PARENT,
                MainnetBlockHeaderValidator.TIMESTAMP_TOLERANCE_S,
                clock),
            gasLimitCalculator);

    final EthHashMiningCoordinator miningCoordinator =
        new EthHashMiningCoordinator(
            protocolContext.getBlockchain(),
            executor,
            syncState,
            miningParameters.getRemoteSealersLimit(),
            miningParameters.getRemoteSealersTimeToLive());
    miningCoordinator.addMinedBlockObserver(ethProtocolManager);
    miningCoordinator.setStratumMiningEnabled(miningParameters.isStratumMiningEnabled());
    if (miningParameters.isMiningEnabled()) {
      miningCoordinator.enable();
    }

    return miningCoordinator;
  }

  @Override
  protected Void createConsensusContext(
      final Blockchain blockchain, final WorldStateArchive worldStateArchive) {
    return null;
  }

  @Override
  protected PluginServiceFactory createAdditionalPluginServices(final Blockchain blockchain) {
    return new NoopPluginServiceFactory();
  }

  @Override
  protected ProtocolSchedule createProtocolSchedule() {
    return MainnetProtocolSchedule.fromConfig(
        genesisConfig.getConfigOptions(genesisConfigOverrides),
        privacyParameters,
        isRevertReasonEnabled);
  }
}
