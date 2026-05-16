class Zm < Formula
  desc "Fast, safe archive utility for ZIP, 7z, TAR.ZST, and broad extraction"
  homepage "https://github.com/frankmanzhu/zmanager"
  url "https://github.com/frankmanzhu/zmanager.git",
      tag: "v0.1.0"
  license all_of: ["MIT", :cannot_represent]
  head "https://github.com/frankmanzhu/zmanager.git", branch: "main"

  depends_on "cmake" => :build
  depends_on "rust" => :build

  depends_on "libb2"
  depends_on "lz4"
  depends_on "xz"
  depends_on "zstd"

  uses_from_macos "bzip2"
  uses_from_macos "libxml2"
  uses_from_macos "zlib"

  on_linux do
    depends_on "acl"
    depends_on "bzip2"
    depends_on "libxml2"
    depends_on "openssl@3"
    depends_on "zlib"
  end

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/zmanager-cli")
  end

  test do
    assert_match "Usage:", shell_output("#{bin}/zm --help")

    (testpath/"payload.txt").write("hello from Homebrew\n")
    system bin/"zm", "create", "payload.zip", "payload.txt"
    system bin/"zm", "test", "payload.zip"
  end
end
