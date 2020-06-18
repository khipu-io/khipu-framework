package khipu.cli.presynctasks;

import khipu.controller.BesuController;
import khipu.util.PrivateStorageMigrationBuilder;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.privacy.storage.migration.PrivateStorageMigrationService;

public class PrivateDatabaseMigrationPreSyncTask implements PreSynchronizationTask {

  private final PrivacyParameters privacyParameters;
  private final boolean migratePrivateDatabaseFlag;

  public PrivateDatabaseMigrationPreSyncTask(
      final PrivacyParameters privacyParameters, final boolean migratePrivateDatabaseFlag) {
    this.privacyParameters = privacyParameters;
    this.migratePrivateDatabaseFlag = migratePrivateDatabaseFlag;
  }

  @Override
  public void run(final BesuController besuController) {
    final PrivateStorageMigrationBuilder privateStorageMigrationBuilder =
        new PrivateStorageMigrationBuilder(besuController, privacyParameters);
    final PrivateStorageMigrationService privateStorageMigrationService =
        new PrivateStorageMigrationService(
            privacyParameters.getPrivateStateStorage(),
            migratePrivateDatabaseFlag,
            privateStorageMigrationBuilder::build);

    privateStorageMigrationService.runMigrationIfRequired();
  }
}
