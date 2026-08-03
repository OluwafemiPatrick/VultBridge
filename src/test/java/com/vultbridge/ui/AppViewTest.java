package com.vultbridge.ui;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.vultbridge.platform.FileDialogService;
import com.vultbridge.service.BackgroundJobManager;
import com.vultbridge.service.VaultService;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TableView;
import javafx.stage.Stage;
import javafx.stage.Window;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.testfx.api.FxRobot;
import org.testfx.framework.junit5.ApplicationExtension;
import org.testfx.framework.junit5.Start;
import org.testfx.util.WaitForAsyncUtils;

@ExtendWith(ApplicationExtension.class)
class AppViewTest {
  private static final String COMPACTED_OUTPUT_PATTERN =
      "ui-workflow-\\d{8}T\\d{6}Z-[0-9a-f]{6}\\.vltb";

  @TempDir Path temporaryDirectory;
  private AppView appView;
  private WorkflowDialogs dialogs;

  @Start
  void start(Stage stage) throws Exception {
    Path vault = temporaryDirectory.resolve("ui-workflow.vltb");
    Path accepted = temporaryDirectory.resolve("accepted.bin");
    Files.write(accepted, new byte[] {1, 2, 3});
    dialogs = new WorkflowDialogs(vault, List.of(accepted, temporaryDirectory));
    appView =
        new AppView(dialogs, new BackgroundJobManager(Platform::runLater), new VaultService());
    stage.setScene(new Scene(appView, 760, 480));
    stage.show();
  }

  @AfterEach
  void closeView(FxRobot robot) {
    robot.interact(appView::close);
  }

  @Test
  void entersAndCancelsCreateVaultScreen(FxRobot robot) {
    fire(robot, "#create-vault-button");
    assertNotNull(robot.lookup("#create-vault-view").query());

    fire(robot, "#create-back-button");
    assertNotNull(robot.lookup("#welcome-view").query());
  }

  @Test
  void clearsOpenPassphraseWhenLeavingScreen(FxRobot robot) {
    fire(robot, "#open-vault-button");
    var firstPassphrase = robot.lookup("#existing-passphrase").queryAs(PasswordField.class);
    robot.interact(() -> firstPassphrase.setText("temporary secret"));
    fire(robot, "#open-back-button");

    fire(robot, "#open-vault-button");
    var passphrase = robot.lookup("#existing-passphrase").queryAs(PasswordField.class);
    assertEquals("", passphrase.getText());
  }

  @Test
  void refreshesCommittedFilesWhenALaterImportIsRejected(FxRobot robot) throws Exception {
    createAndUnlock(robot);

    fire(robot, "#import-files-button");
    waitUntil(
        () -> {
          if (robot.lookup("#vault-file-table").queryAll().isEmpty()) {
            return false;
          }
          TableView<?> table = robot.lookup("#vault-file-table").query();
          var importButton = robot.lookup("#import-files-button").queryAs(Button.class);
          return table.getItems().size() == 1 && !importButton.isDisabled();
        });

    TableView<?> table = robot.lookup("#vault-file-table").query();
    assertEquals(1, table.getItems().size());
    assertEquals("accepted.bin", ((VaultItemViewModel) table.getItems().getFirst()).displayName());
  }

  @Test
  void exportsAndDeletesTheSelectedFile(FxRobot robot) throws Exception {
    createAndUnlock(robot);
    dialogs.setImports(List.of(temporaryDirectory.resolve("accepted.bin")));
    fire(robot, "#import-files-button");
    waitUntil(() -> selectedFileActionsAreReady(robot));

    TableView<?> table = robot.lookup("#vault-file-table").query();
    robot.interact(() -> table.getSelectionModel().selectFirst());
    waitUntil(
        () ->
            !robot.lookup("#export-file-button").queryAs(Button.class).isDisabled()
                && !robot.lookup("#delete-file-button").queryAs(Button.class).isDisabled());

    Path exported = temporaryDirectory.resolve("exported.bin");
    dialogs.setExportDestination(exported);
    fire(robot, "#export-file-button");
    waitUntil(
        () ->
            Files.exists(exported)
                && !robot.lookup("#import-files-button").queryAs(Button.class).isDisabled());
    assertArrayEquals(new byte[] {1, 2, 3}, Files.readAllBytes(exported));

    TableView<?> refreshedTable = robot.lookup("#vault-file-table").query();
    robot.interact(() -> refreshedTable.getSelectionModel().selectFirst());
    waitUntil(() -> !robot.lookup("#delete-file-button").queryAs(Button.class).isDisabled());
    Button deleteButton = robot.lookup("#delete-file-button").queryAs(Button.class);
    Platform.runLater(deleteButton::fire);
    waitUntil(() -> findVisibleButton("Acknowledge").isPresent());
    robot.interact(() -> findVisibleButton("Acknowledge").orElseThrow().fire());
    waitUntil(
        () ->
            robot.lookup("#vault-file-table").queryAs(TableView.class).getItems().isEmpty()
                && !robot.lookup("#import-files-button").queryAs(Button.class).isDisabled());
  }

  @Test
  void confirmsAndCompletesCompactionThroughTheBackgroundWorkflow(FxRobot robot) throws Exception {
    createAndUnlock(robot);
    dialogs.setImports(List.of(temporaryDirectory.resolve("accepted.bin")));
    fire(robot, "#import-files-button");
    waitUntil(() -> selectedFileActionsAreReady(robot));

    dialogs.setCompactionDirectory(temporaryDirectory);
    fire(robot, "#compact-vault-button");
    waitUntil(() -> findVisibleButton("Start compaction").isPresent());
    robot.interact(() -> findVisibleButton("Start compaction").orElseThrow().fire());

    Path source = temporaryDirectory.resolve("ui-workflow.vltb");
    waitUntil(() -> !Files.exists(source) && compactedOutputExists(temporaryDirectory));
    assertTrue(robot.lookup("#unlocked-vault-view").queryAll().size() == 1);
  }

  @Test
  void lockRemainsAvailableAndWaitsForActiveImportCancellation(FxRobot robot) throws Exception {
    createAndUnlock(robot);
    Path large = temporaryDirectory.resolve("large-active-import.bin");
    try (var channel =
        FileChannel.open(large, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
      channel.position(64L * 1024 * 1024 - 1);
      channel.write(ByteBuffer.wrap(new byte[] {1}));
    }
    dialogs.setImports(List.of(large));

    fire(robot, "#import-files-button");
    waitUntil(
        () -> {
          if (robot.lookup("#lock-vault-button").queryAll().isEmpty()) {
            return false;
          }
          var lock = robot.lookup("#lock-vault-button").queryAs(Button.class);
          var importButton = robot.lookup("#import-files-button").queryAs(Button.class);
          return !lock.isDisabled() && importButton.isDisabled();
        });
    assertFalse(robot.lookup("#lock-vault-button").queryAs(Button.class).isDisabled());

    fire(robot, "#lock-vault-button");
    waitUntil(() -> !robot.lookup("#welcome-view").queryAll().isEmpty());
    assertNotNull(robot.lookup("#welcome-view").query());
  }

  private static void fire(FxRobot robot, String selector) {
    var button = robot.lookup(selector).queryAs(Button.class);
    robot.interact(button::fire);
  }

  private static void createAndUnlock(FxRobot robot) throws InterruptedException {
    fire(robot, "#create-vault-button");
    fire(robot, "#choose-new-vault-button");
    robot.interact(
        () -> {
          robot
              .lookup("#new-passphrase")
              .queryAs(PasswordField.class)
              .setText("correct horse battery staple");
          robot
              .lookup("#confirm-passphrase")
              .queryAs(PasswordField.class)
              .setText("correct horse battery staple");
          robot.lookup(".check-box").queryAs(CheckBox.class).setSelected(true);
        });
    fire(robot, "#submit-create-vault-button");
    waitUntil(() -> !robot.lookup("#unlocked-vault-view").queryAll().isEmpty());
  }

  private static void waitUntil(BooleanSupplier condition) throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
    while (!condition.getAsBoolean() && System.nanoTime() < deadline) {
      WaitForAsyncUtils.waitForFxEvents();
      TimeUnit.MILLISECONDS.sleep(20);
    }
    assertTrue(condition.getAsBoolean(), "Timed out waiting for the JavaFX workflow");
  }

  private static boolean selectedFileActionsAreReady(FxRobot robot) {
    if (robot.lookup("#vault-file-table").queryAll().isEmpty()) {
      return false;
    }
    TableView<?> table = robot.lookup("#vault-file-table").query();
    return table.getItems().size() == 1
        && !robot.lookup("#import-files-button").queryAs(Button.class).isDisabled();
  }

  private static boolean compactedOutputExists(Path directory) {
    try (var paths = Files.list(directory)) {
      return paths.anyMatch(
          path -> {
            Path fileName = path.getFileName();
            return fileName != null && fileName.toString().matches(COMPACTED_OUTPUT_PATTERN);
          });
    } catch (java.io.IOException exception) {
      return false;
    }
  }

  private static Optional<Button> findVisibleButton(String text) {
    return Window.getWindows().stream()
        .filter(Window::isShowing)
        .filter(window -> window.getScene() != null)
        .flatMap(window -> window.getScene().getRoot().lookupAll(".button").stream())
        .filter(Button.class::isInstance)
        .map(Button.class::cast)
        .filter(button -> text.equals(button.getText()))
        .findFirst();
  }

  private static final class WorkflowDialogs implements FileDialogService {
    private final Path vault;
    private List<Path> imports;
    private Optional<Path> exportDestination = Optional.empty();
    private Optional<Path> compactionDirectory = Optional.empty();

    private WorkflowDialogs(Path vault, List<Path> imports) {
      this.vault = vault;
      this.imports = List.copyOf(imports);
    }

    private void setImports(List<Path> imports) {
      this.imports = List.copyOf(imports);
    }

    private void setExportDestination(Path destination) {
      exportDestination = Optional.of(destination);
    }

    private void setCompactionDirectory(Path destination) {
      compactionDirectory = Optional.of(destination);
    }

    @Override
    public Optional<Path> chooseNewVault(Window owner) {
      return Optional.of(vault);
    }

    @Override
    public Optional<Path> chooseExistingVault(Window owner) {
      return Optional.empty();
    }

    @Override
    public List<Path> chooseImportFiles(Window owner) {
      return imports;
    }

    @Override
    public Optional<Path> chooseExportDestination(Window owner, String suggestedName) {
      return exportDestination;
    }

    @Override
    public Optional<Path> chooseCompactionDirectory(Window owner) {
      return compactionDirectory;
    }
  }
}
