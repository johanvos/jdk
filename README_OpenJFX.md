#Building OpenJDK with OpenJFX

- make sure you have an OpenJFX clone locally, e.g. at /path/to/openjfx

- configure: `configure --with-conf-name=jfx0326 --with-openjfx-modules=/path/to/openjfx --disable-warnings-as-errors`

- build: 
-- `cd build/jfx0326`
-- `make jdk`



