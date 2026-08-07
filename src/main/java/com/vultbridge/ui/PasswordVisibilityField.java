package com.vultbridge.ui;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.scene.shape.Ellipse;

/**
 * Provides a password field with an explicit, default-hidden visibility toggle.
 *
 * <p>The masked and revealed controls are kept synchronized and both are cleared by {@link
 * #clear()}. The revealed control exists only for the user's explicit visibility choice; no
 * clipboard or persistence behavior is added.
 */
final class PasswordVisibilityField extends StackPane {
  private final PasswordField maskedField = new PasswordField();
  private final TextField revealedField = new TextField();
  private final Button visibilityButton = new Button();
  private boolean revealed;

  PasswordVisibilityField(String id, String promptText) {
    maskedField.setId(id);
    maskedField.setPromptText(promptText);
    maskedField.setPadding(new Insets(0, 36, 0, 8));
    revealedField.setId(id + "-visible");
    revealedField.setPromptText(promptText);
    revealedField.setPadding(new Insets(0, 36, 0, 8));

    revealedField.setVisible(false);
    revealedField.setManaged(false);
    maskedField
        .textProperty()
        .addListener(
            (observable, oldValue, newValue) -> {
              if (!revealed && !newValue.equals(revealedField.getText())) {
                revealedField.setText(newValue);
              }
            });
    revealedField
        .textProperty()
        .addListener(
            (observable, oldValue, newValue) -> {
              if (revealed && !newValue.equals(maskedField.getText())) {
                maskedField.setText(newValue);
              }
            });

    visibilityButton.setId(id + "-visibility-toggle");
    visibilityButton.setGraphic(eyeIcon());
    visibilityButton.setTooltip(new Tooltip("Show passphrase"));
    visibilityButton.setAccessibleText("Show passphrase");
    visibilityButton.setFocusTraversable(true);
    visibilityButton.getStyleClass().add("password-visibility-toggle");
    visibilityButton.setOnAction(event -> setRevealed(!revealed));

    setMaxWidth(Double.MAX_VALUE);
    StackPane.setAlignment(visibilityButton, Pos.CENTER_RIGHT);
    StackPane.setMargin(visibilityButton, new Insets(0, 3, 0, 0));
    getChildren().addAll(maskedField, revealedField, visibilityButton);
  }

  /** Returns the text currently owned by the active input control. */
  String getText() {
    return revealed ? revealedField.getText() : maskedField.getText();
  }

  /** Clears both JavaFX controls and returns the field to its default masked state. */
  void clear() {
    maskedField.clear();
    revealedField.clear();
    setRevealed(false);
  }

  private void setRevealed(boolean value) {
    if (revealed == value) {
      return;
    }
    if (value) {
      revealedField.setText(maskedField.getText());
    } else {
      maskedField.setText(revealedField.getText());
    }
    revealed = value;
    maskedField.setVisible(!value);
    maskedField.setManaged(!value);
    revealedField.setVisible(value);
    revealedField.setManaged(value);
    String label = value ? "Hide passphrase" : "Show passphrase";
    visibilityButton.setTooltip(new Tooltip(label));
    visibilityButton.setAccessibleText(label);
  }

  private static Node eyeIcon() {
    var outline = new Ellipse(8, 5);
    outline.setFill(Color.TRANSPARENT);
    outline.setStroke(Color.web("#626b68"));
    outline.setStrokeWidth(1.2);
    var pupil = new Circle(2, Color.web("#626b68"));
    var icon = new StackPane(outline, pupil);
    icon.setMouseTransparent(true);
    return icon;
  }
}
