package com.vultbridge.app;

import com.vultbridge.ui.WelcomeView;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

/** JavaFX entry point for VultBridge. */
public final class VultBridgeApplication extends Application {
  private static final double INITIAL_WIDTH = 760;
  private static final double INITIAL_HEIGHT = 480;

  /** Creates the JavaFX application instance. */
  public VultBridgeApplication() {}

  @Override
  public void start(Stage stage) {
    var scene = new Scene(new WelcomeView(), INITIAL_WIDTH, INITIAL_HEIGHT);
    var stylesheet = VultBridgeApplication.class.getResource("/com/vultbridge/vultbridge.css");
    if (stylesheet != null) {
      scene.getStylesheets().add(stylesheet.toExternalForm());
    }

    stage.setTitle(AppInfo.NAME);
    stage.setMinWidth(640);
    stage.setMinHeight(400);
    stage.setScene(scene);
    stage.show();
  }

  public static void main(String[] args) {
    launch(args);
  }
}
