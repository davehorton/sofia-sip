with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "sofia-sip";
  src = ./.;

  buildInputs = [ gcc autoconf automake gnumake libtool openssl which gawk pkg-config ];

  buildPhase = ''
    autoupdate
    ./bootstrap.sh
    ./configure --with-glib=no
    make
  '';

  installPhase = ''
    mkdir -p $out
    cp -r * $out/
  '';
}