# logging_config.py
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("security_app.log"),
        logging.StreamHandler()
    ]
)
