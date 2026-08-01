package com.vultbridge.app;

import com.vultbridge.ui.AppView;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * JavaFX process entry point and owner of the application-wide UI lifecycle.
 *
 * <p>It creates the single application view, applies the shared stylesheet, and guarantees that
 * sensitive controls and background resources are closed when JavaFX stops.
 */
public final class VultBridgeApplication extends Application {
  private static final double INITIAL_WIDTH = 760;
  private static final double INITIAL_HEIGHT = 480;
  private AppView appView;

  /** Creates the JavaFX application instance. */
  public VultBridgeApplication() {}

  // Builds and displays the primary application window.
  @Override
  public void start(Stage stage) {
    appView = new AppView();
    var scene = new Scene(appView, INITIAL_WIDTH, INITIAL_HEIGHT);
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

  // Releases sensitive view state and the background worker during JavaFX shutdown.
  @Override
  public void stop() {
    if (appView != null) {
      appView.close();
    }
  }

  /** Launches JavaFX when the application is started from a conventional Java entry point. */
  public static void main(String[] args) {
    launch(args);
  }
}
