import mariadb


# ==========================================================
# Import Local Module
# ==========================================================

from config import DB_CONFIG


# ==========================================================
# Database Connection Class
# ==========================================================

class DatabaseConnection:

    def __init__(self):
        self.connection = None


    def connect(self):

        if self.connection is None:

            try:
                self.connection = mariadb.connect(**DB_CONFIG)

            except mariadb.Error as err:
                raise ConnectionError(
                    f"Failed to connect to MariaDB: {err}"
                )

        return self.connection


    def cursor(self):

        if self.connection is None:
            self.connect()

        return self.connection.cursor()


    def commit(self):

        if self.connection:
            self.connection.commit()


    def rollback(self):

        if self.connection:
            self.connection.rollback()


    def close(self):

        if self.connection:

            self.connection.close()

            self.connection = None