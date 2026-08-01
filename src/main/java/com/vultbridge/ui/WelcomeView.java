package com.vultbridge.ui;

import java.util.Objects;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

/**
 * Presents the initial choice to create a new vault or open an existing one.
 *
 * <p>The view is intentionally stateless: both actions delegate navigation to the application state
 * machine supplied by its parent.
 */
public final class WelcomeView extends VBox {
  /** Creates the Welcome screen with navigation actions for its two supported workflows. */
  public WelcomeView(Runnable showCreateVault, Runnable showOpenVault) {
    Objects.requireNonNull(showCreateVault, "showCreateVault");
    Objects.requireNonNull(showOpenVault, "showOpenVault");

    setId("welcome-view");
    getStyleClass().addAll("content-view", "welcome");
    setAlignment(Pos.CENTER);
    setPadding(new Insets(48));
    setSpacing(14);

    var title = new Label("VultBridge");
    title.getStyleClass().add("title");

    var description =
        new Label(
            "Create or open a portable encrypted vault. Files remain encrypted until the vault "
                + "is unlocked with your passphrase.");
    description.getStyleClass().add("description");
    description.setMaxWidth(480);
    description.setWrapText(true);

    var createButton = new Button("Create a new vault");
    createButton.setId("create-vault-button");
    createButton.getStyleClass().add("primary-button");
    createButton.setOnAction(event -> showCreateVault.run());

    var openButton = new Button("Open an existing vault");
    openButton.setId("open-vault-button");
    openButton.setOnAction(event -> showOpenVault.run());

    var actions = new HBox(10, createButton, openButton);
    actions.setAlignment(Pos.CENTER);

    var status = new Label("No account, cloud service, or passphrase recovery.");
    status.getStyleClass().add("status");

    getChildren().addAll(title, description, actions, status);
  }
}
