import pathlib
import royalnet.scrolls as s
import royalnet.lazy as lazy


lazy_config = lazy.Lazy(lambda: s.Scroll.from_file("RYGLFG", pathlib.Path("config.toml")))


__all__ = (
    "lazy_config",
)
