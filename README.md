# Personal notes


## getting started
```bash
docker run --rm -it -v ./:/docs squidfunk/mkdocs-material new .
```

## start local preview

```bash
docker run --rm -it -p 8000:8000 -v ./:/docs squidfunk/mkdocs-material

```