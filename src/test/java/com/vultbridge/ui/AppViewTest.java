package com.vultbridge.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.stage.Stage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testfx.api.FxRobot;
import org.testfx.framework.junit5.ApplicationExtension;
import org.testfx.framework.junit5.Start;

@ExtendWith(ApplicationExtension.class)
class AppViewTest {
  @Start
  void start(Stage stage) {
    stage.setScene(new Scene(new AppView(), 760, 480));
    stage.show();
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

  private static void fire(FxRobot robot, String selector) {
    var button = robot.lookup(selector).queryAs(Button.class);
    robot.interact(button::fire);
  }
}
