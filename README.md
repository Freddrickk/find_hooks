# Find hooks

## Description

Find hooks is a small tool that compares executable memory to files on disk to find hooks.

## TODO

- [ ] Don't scan relocs
- [ ] Why does R6S closes on specific libs?

## Compilation

- First, fetch the external dependencies

```bash
git submodule sync
git submodule update --init --recursive
```

## Debug build

- To build in Debug mode:

```bash
mkdir _build
cd _build
cmake -DLIEF_PYTHON_API=off -DCMAKE_BUILD_TYPE=Debug -DLIEF_USE_CRT_DEBUG=MTd ..
cmake --build . --config Debug
```

## Release build

- To build in Release mode:

```bash
mkdir _build
cd _build
cmake -DLIEF_PYTHON_API=off -DCMAKE_BUILD_TYPE=Release -DLIEF_USE_CRT_RELEASE=MT ..
cmake --build . --config Release
```