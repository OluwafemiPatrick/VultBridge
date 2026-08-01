module com.vultbridge {
  requires javafx.controls;
  requires org.bouncycastle.provider;

  exports com.vultbridge.app to
      javafx.graphics;
}
