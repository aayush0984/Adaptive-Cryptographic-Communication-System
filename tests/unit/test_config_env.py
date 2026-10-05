from config import get_env


def test_dotenv_values_are_available() -> None:
    assert get_env("SERVER_HOST") == "127.0.0.1"
    assert get_env("SERVER_PORT") == "5000"
    assert get_env("MONGODB_DB") == "iot_security"
