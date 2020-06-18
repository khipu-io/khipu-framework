package khipu.cli.presynctasks;

import java.util.ArrayList;
import java.util.List;
import khipu.controller.BesuController;

public class PreSynchronizationTaskRunner {

  private final List<PreSynchronizationTask> tasks = new ArrayList<>();

  public void addTask(final PreSynchronizationTask task) {
    tasks.add(task);
  }

  public void runTasks(final BesuController besuController) {
    tasks.forEach(t -> t.run(besuController));
  }
}
