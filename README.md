# Welcome to the JDK!

For build instructions please see the
[online documentation](https://openjdk.org/groups/build/doc/building.html),
or either of these files:

- [doc/building.html](doc/building.html) (html version)
- [doc/building.md](doc/building.md) (markdown version)

See <https://openjdk.org/> for more information about the OpenJDK
Community and the JDK and see <https://bugs.openjdk.org> for JDK issue
tracking.

# Building a JDK with JavaFX modules

This branch contains the source code for the `javafx.base`,
`javafx.graphics` and `javafx.controls` modules for Linux x86.

To build a JDK with these modules, it is assumed that you can build
a regular JDK. The changes required for building the JavaFX modules
are minimal:

`sh configure --with-boot-jdk=/opt/jdk-24-internal --disable-warnings-as-errors`

Make sure to replace `/opt/jdk-24-internal` with your own boot jdk.

Next, cd into the `build/linux-x86_64-server-release` directory and 
build the jdk:
`make jdk`

