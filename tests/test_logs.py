"""
Tests du format des logs JSON émis par Flask.
Vérifie que chaque événement d'auth produit les champs attendus par les décodeurs Wazuh.
"""
import json
import logging


def _get_log_records(caplog, client, action):
    """Exécute action() et retourne les log records capturés."""
    with caplog.at_level(logging.INFO, logger="app.auth.routes"):
        action()
    return caplog.records


class TestLogFormat:
    """Vérifie que les logs émis ont le bon format pour Wazuh."""

    REQUIRED_FIELDS = {"event_type", "user", "ip", "user_agent"}

    def _find_auth_record(self, records):
        """Retourne le premier record avec un event_type (événement auth)."""
        for r in records:
            if hasattr(r, "event_type"):
                return r
        return None

    def test_login_fail_log_fields(self, client, user, caplog):
        """Un échec de connexion doit émettre event_type=login_fail avec les bons champs."""
        with caplog.at_level(logging.INFO, logger="app.auth.routes"):
            client.post("/auth/login", data={"identifier": "testuser", "password": "wrong"})

        record = self._find_auth_record(caplog.records)
        assert record is not None, "Aucun log d'auth émis pour un login_fail"
        assert record.event_type == "login_fail"
        assert record.user == "testuser"
        assert record.ip is not None
        for field in self.REQUIRED_FIELDS:
            assert hasattr(record, field), f"Champ manquant dans le log : {field}"

    def test_login_success_log_fields(self, client, user, caplog):
        """Une connexion réussie doit émettre event_type=login_success."""
        with caplog.at_level(logging.INFO, logger="app.auth.routes"):
            client.post("/auth/login", data={"identifier": "testuser", "password": "password123"})

        records = [r for r in caplog.records if hasattr(r, "event_type") and r.event_type == "login_success"]
        assert len(records) >= 1, "Aucun log login_success émis"
        record = records[0]
        assert record.user == "testuser"
        for field in self.REQUIRED_FIELDS:
            assert hasattr(record, field), f"Champ manquant : {field}"

    def test_account_locked_log_fields(self, app, client, user, caplog):
        """Après 10 échecs, un log account_locked doit être émis."""
        with caplog.at_level(logging.INFO, logger="app.auth.routes"):
            for _ in range(10):
                client.post("/auth/login", data={"identifier": "testuser", "password": "wrong"})

        locked_records = [r for r in caplog.records if hasattr(r, "event_type") and r.event_type == "account_locked"]
        assert len(locked_records) >= 1, "Aucun log account_locked émis après 10 échecs"
        record = locked_records[0]
        assert record.user == "testuser"

    def test_register_log_fields(self, client, caplog):
        """Une inscription réussie doit émettre event_type=register."""
        with caplog.at_level(logging.INFO, logger="app.auth.routes"):
            client.post("/auth/register", data={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "password123",
                "confirm_password": "password123",
            })

        records = [r for r in caplog.records if hasattr(r, "event_type") and r.event_type == "register"]
        assert len(records) >= 1, "Aucun log register émis"
        assert records[0].user == "newuser"

    def test_logout_log_fields(self, logged_in_client, caplog):
        """Une déconnexion doit émettre event_type=logout."""
        with caplog.at_level(logging.INFO, logger="app.auth.routes"):
            logged_in_client.get("/auth/logout")

        records = [r for r in caplog.records if hasattr(r, "event_type") and r.event_type == "logout"]
        assert len(records) >= 1, "Aucun log logout émis"

    def test_log_json_serializable(self, client, user, caplog):
        """Les champs du log doivent être sérialisables en JSON (format Wazuh)."""
        with caplog.at_level(logging.INFO, logger="app.auth.routes"):
            client.post("/auth/login", data={"identifier": "testuser", "password": "wrong"})

        record = self._find_auth_record(caplog.records)
        assert record is not None

        log_dict = {
            "event_type": record.event_type,
            "user": record.user,
            "ip": record.ip,
            "user_agent": record.user_agent,
            "details": getattr(record, "details", None),
        }
        # Ne doit pas lever d'exception
        serialized = json.dumps(log_dict)
        parsed = json.loads(serialized)
        assert parsed["event_type"] == "login_fail"

    def test_anonymous_login_fail_log(self, client, caplog):
        """Un login fail sur un utilisateur inexistant doit logger user=anonymous."""
        with caplog.at_level(logging.INFO, logger="app.auth.routes"):
            client.post("/auth/login", data={"identifier": "ghost", "password": "wrong"})

        record = self._find_auth_record(caplog.records)
        assert record is not None
        assert record.event_type == "login_fail"
        assert record.user == "anonymous"


class TestWazuhDecoderContract:
    """
    Vérifie que les champs Flask correspondent exactement
    à ce qu'attendent les décodeurs Wazuh (local_decoders.xml).

    Champs requis par flask-secureapp-auth :
      event_type, user, ip
    """

    def test_event_type_values_are_known(self, client, user, caplog):
        """Les event_type émis doivent faire partie des valeurs connues par Wazuh."""
        known_types = {
            "login_fail", "login_success", "mfa_fail", "mfa_success",
            "account_locked", "register", "logout", "password_reset",
            "password_reset_request",
        }

        with caplog.at_level(logging.INFO, logger="app.auth.routes"):
            client.post("/auth/login", data={"identifier": "testuser", "password": "wrong"})

        for record in caplog.records:
            if hasattr(record, "event_type"):
                assert record.event_type in known_types, (
                    f"event_type inconnu des règles Wazuh : '{record.event_type}'"
                )

    def test_ip_field_is_string(self, client, user, caplog):
        """Le champ ip doit être une string (parseable par le décodeur Wazuh)."""
        with caplog.at_level(logging.INFO, logger="app.auth.routes"):
            client.post("/auth/login", data={"identifier": "testuser", "password": "wrong"})

        for record in caplog.records:
            if hasattr(record, "ip"):
                assert isinstance(record.ip, str), "Le champ ip doit être une string"
                break
