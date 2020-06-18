package khipu.util;

import khipu.controller.BesuController;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.privacy.PrivateStateRootResolver;
import org.hyperledger.besu.ethereum.privacy.storage.LegacyPrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.migration.PrivateMigrationBlockProcessor;
import org.hyperledger.besu.ethereum.privacy.storage.migration.PrivateStorageMigration;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

public class PrivateStorageMigrationBuilder {

  private final BesuController besuController;
  private final PrivacyParameters privacyParameters;

  public PrivateStorageMigrationBuilder(
      final BesuController besuController, final PrivacyParameters privacyParameters) {
    this.besuController = besuController;
    this.privacyParameters = privacyParameters;
  }

  public PrivateStorageMigration build() {
    final Blockchain blockchain = besuController.getProtocolContext().getBlockchain();
    final Address privacyPrecompileAddress =
        Address.privacyPrecompiled(privacyParameters.getPrivacyAddress());
    final ProtocolSchedule protocolSchedule = besuController.getProtocolSchedule();
    final WorldStateArchive publicWorldStateArchive =
        besuController.getProtocolContext().getWorldStateArchive();
    final PrivateStateStorage privateStateStorage = privacyParameters.getPrivateStateStorage();
    final LegacyPrivateStateStorage legacyPrivateStateStorage =
        privacyParameters.getPrivateStorageProvider().createLegacyPrivateStateStorage();
    final PrivateStateRootResolver privateStateRootResolver =
        privacyParameters.getPrivateStateRootResolver();

    return new PrivateStorageMigration(
        blockchain,
        privacyPrecompileAddress,
        protocolSchedule,
        publicWorldStateArchive,
        privateStateStorage,
        privateStateRootResolver,
        legacyPrivateStateStorage,
        PrivateMigrationBlockProcessor::new);
  }
}
