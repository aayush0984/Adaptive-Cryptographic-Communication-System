"""Script entrypoint to create MongoDB database indexes."""

from database.indexes import create_indexes

if __name__ == "__main__":
    result = create_indexes()
    print("Created indexes:", result)
