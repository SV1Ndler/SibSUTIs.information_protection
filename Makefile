all:
	@cmake --preset="debug"
	@cmake --build --preset="debug"
	@ctest --preset debug
