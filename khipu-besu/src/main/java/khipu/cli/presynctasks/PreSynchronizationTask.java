package khipu.cli.presynctasks;

import khipu.controller.BesuController;

/**
 * All PreSynchronizationTask instances execute after the {@link BesuController} instance in {@link
 * BesuCommand} is ready and before {@link BesuCommand#startSynchronization()} is called
 */
public interface PreSynchronizationTask {

  void run(final BesuController besuController);
}
