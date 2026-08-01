module com.vultbridge {
  requires com.fasterxml.jackson.core;
  requires com.fasterxml.jackson.dataformat.cbor;
  requires javafx.controls;
  requires org.bouncycastle.provider;

  exports com.vultbridge.app to
      javafx.graphics;
}
