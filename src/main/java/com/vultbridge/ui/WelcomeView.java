package com.vultbridge.ui;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;

/** Initial application view. Vault actions remain disabled until their Phase 1 flows exist. */
public final class WelcomeView extends VBox {
  public WelcomeView() {
    getStyleClass().add("welcome");
    setAlignment(Pos.CENTER);
    setPadding(new Insets(48));
    setSpacing(18);

    var title = new Label("VultBridge");
    title.getStyleClass().add("title");

    var description = new Label("A portable, encrypted home for your private files.");
    description.getStyleClass().add("description");
    description.setWrapText(true);

    var createButton = new Button("Create vault");
    createButton.setDisable(true);
    createButton.setAccessibleHelp("Vault creation is not available in this build.");

    var openButton = new Button("Open vault");
    openButton.setDisable(true);
    openButton.setAccessibleHelp("Vault opening is not available in this build.");

    var status = new Label("Phase 1 application shell");
    status.getStyleClass().add("status");

    getChildren().addAll(title, description, createButton, openButton, status);
  }
}
