import html
import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

import streamlit as st
from streamlit.errors import StreamlitSecretNotFoundError


DATABASE_PATH = Path(__file__).resolve().with_name("meu_treino.db")
PASSWORD_ITERATIONS = 310_000
ADMIN_USERNAME = "JJadm"


def get_admin_password() -> str | None:
    password = os.environ.get("MEU_TREINO_ADMIN_PASSWORD")
    if password:
        return password

    try:
        password = st.secrets.get("admin_password")
    except StreamlitSecretNotFoundError:
        return None
    return str(password) if password else None


@contextmanager
def database_connection() -> Generator[sqlite3.Connection, None, None]:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        is not None
    )


def init_db() -> bool:
    with database_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome_usuario TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                tipo TEXT NOT NULL DEFAULT 'comum'
            );
            CREATE TABLE IF NOT EXISTS treinos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL
                    REFERENCES usuarios(id) ON DELETE CASCADE,
                nome TEXT NOT NULL,
                divisao TEXT NOT NULL DEFAULT '',
                data TEXT NOT NULL DEFAULT '',
                notas TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS exercicios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                treino_id INTEGER NOT NULL
                    REFERENCES treinos(id) ON DELETE CASCADE,
                nome TEXT NOT NULL,
                series INTEGER NOT NULL CHECK (series > 0),
                repeticoes TEXT NOT NULL,
                descanso TEXT NOT NULL DEFAULT '60s',
                notas TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS app_migrations (
                nome TEXT PRIMARY KEY
            );
            """
        )

        exercise_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(exercicios)")
        }
        if "descanso" not in exercise_columns:
            connection.execute(
                """
                CREATE TABLE exercicios_novo (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    treino_id INTEGER NOT NULL
                        REFERENCES treinos(id) ON DELETE CASCADE,
                    nome TEXT NOT NULL,
                    series INTEGER NOT NULL CHECK (series > 0),
                    repeticoes TEXT NOT NULL,
                    descanso TEXT NOT NULL DEFAULT '60s',
                    notas TEXT NOT NULL DEFAULT ''
                )
                """
            )
            connection.execute(
                """
                INSERT INTO exercicios_novo
                    (id, treino_id, nome, series, repeticoes, descanso, notas)
                SELECT id, treino_id, nome, series, repeticoes, '60s', notas
                FROM exercicios
                """
            )
            connection.execute("DROP TABLE exercicios")
            connection.execute("ALTER TABLE exercicios_novo RENAME TO exercicios")

        user_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(usuarios)")
        }
        if "tipo" not in user_columns:
            connection.execute(
                "ALTER TABLE usuarios ADD COLUMN tipo TEXT NOT NULL DEFAULT 'comum'"
            )

        legacy_migration = connection.execute(
            "SELECT 1 FROM app_migrations WHERE nome = 'legacy_english_schema_v1'"
        ).fetchone()
        if legacy_migration is None:
            if table_exists(connection, "users"):
                connection.execute(
                    """
                    INSERT OR IGNORE INTO usuarios
                        (id, nome_usuario, password_salt, password_hash, tipo)
                    SELECT id, username, password_salt, password_hash, 'comum'
                    FROM users
                    """
                )

            if table_exists(connection, "workouts"):
                connection.execute(
                    """
                    INSERT OR IGNORE INTO treinos
                        (id, usuario_id, nome, divisao, data, notas)
                    SELECT id, user_id, name, '', workout_date, notes FROM workouts
                    """
                )

            if table_exists(connection, "exercises"):
                connection.execute(
                    """
                    INSERT OR IGNORE INTO exercicios
                        (id, treino_id, nome, series, repeticoes, descanso, notas)
                    SELECT id, workout_id, name, sets, CAST(reps AS TEXT), '60s', notes
                    FROM exercises
                    """
                )
            connection.execute(
                "INSERT INTO app_migrations (nome) VALUES ('legacy_english_schema_v1')"
            )

        admin = connection.execute(
            "SELECT id, tipo FROM usuarios WHERE nome_usuario = ?",
            (ADMIN_USERNAME,),
        ).fetchone()
        admin_password = get_admin_password()

        if admin is None and admin_password is None:
            return False
        if admin_password is not None and len(admin_password) < 8:
            raise ValueError(
                "A palavra-passe de administrador deve ter pelo menos 8 caracteres."
            )

        if admin is None:
            salt = secrets.token_bytes(16)
            connection.execute(
                """
                INSERT INTO usuarios
                    (nome_usuario, password_salt, password_hash, tipo)
                VALUES (?, ?, ?, 'admin')
                """,
                (
                    ADMIN_USERNAME,
                    salt.hex(),
                    hash_password(admin_password, salt),
                ),
            )
            return True

        if admin["tipo"] != "admin":
            if admin_password is None:
                return False
            salt = secrets.token_bytes(16)
            connection.execute(
                """
                UPDATE usuarios
                SET tipo = 'admin', password_salt = ?, password_hash = ?
                WHERE id = ?
                """,
                (salt.hex(), hash_password(admin_password, salt), admin["id"]),
            )
        return True

def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    ).hex()


def register_user(username: str, password: str) -> None:
    username = username.strip()
    if not 3 <= len(username) <= 30:
        raise ValueError("O nome de utilizador deve ter entre 3 e 30 caracteres.")
    if username.casefold() == ADMIN_USERNAME.casefold():
        raise ValueError("Esse nome de utilizador está reservado.")
    if len(password) < 8:
        raise ValueError("A palavra-passe deve ter pelo menos 8 caracteres.")

    salt = secrets.token_bytes(16)
    with database_connection() as connection:
        connection.execute(
            """
            INSERT INTO usuarios (nome_usuario, password_salt, password_hash, tipo)
            VALUES (?, ?, ?, 'comum')
            """,
            (username, salt.hex(), hash_password(password, salt)),
        )


def authenticate_user(username: str, password: str) -> sqlite3.Row | None:
    with database_connection() as connection:
        user = connection.execute(
            """
            SELECT id, nome_usuario, password_salt, password_hash, tipo
            FROM usuarios
            WHERE nome_usuario = ?
            """,
            (username.strip(),),
        ).fetchone()

    if user is None:
        return None
    salt = bytes.fromhex(user["password_salt"])
    candidate_hash = hash_password(password, salt)
    if not hmac.compare_digest(candidate_hash, user["password_hash"]):
        return None
    return user


def get_session_user(user_id: int) -> sqlite3.Row | None:
    with database_connection() as connection:
        return connection.execute(
            "SELECT id, nome_usuario, tipo FROM usuarios WHERE id = ?",
            (user_id,),
        ).fetchone()


def require_admin(connection: sqlite3.Connection, admin_id: int) -> None:
    admin = connection.execute(
        """
        SELECT 1 FROM usuarios
        WHERE id = ? AND tipo = 'admin'
          AND nome_usuario = ? COLLATE NOCASE
        """,
        (admin_id, ADMIN_USERNAME),
    ).fetchone()
    if admin is None:
        raise PermissionError("Esta operação requer a conta administradora.")


def get_admin_users(admin_id: int) -> list[sqlite3.Row]:
    with database_connection() as connection:
        require_admin(connection, admin_id)
        return connection.execute(
            """
            SELECT usuarios.id, usuarios.nome_usuario, usuarios.tipo,
                   COUNT(DISTINCT treinos.id) AS total_treinos
            FROM usuarios
            LEFT JOIN treinos ON treinos.usuario_id = usuarios.id
            GROUP BY usuarios.id
            ORDER BY usuarios.nome_usuario COLLATE NOCASE
            """
        ).fetchall()


def get_admin_workouts(admin_id: int) -> list[sqlite3.Row]:
    with database_connection() as connection:
        require_admin(connection, admin_id)
        return connection.execute(
            """
            SELECT treinos.id, treinos.nome, treinos.divisao, treinos.data,
                   usuarios.nome_usuario,
                   COUNT(exercicios.id) AS total_exercicios
            FROM treinos
            JOIN usuarios ON usuarios.id = treinos.usuario_id
            LEFT JOIN exercicios ON exercicios.treino_id = treinos.id
            GROUP BY treinos.id
            ORDER BY treinos.id DESC
            """
        ).fetchall()


def delete_user_account(admin_id: int, user_id: int) -> None:
    if user_id == admin_id:
        raise ValueError("A conta administradora não pode ser apagada.")

    with database_connection() as connection:
        require_admin(connection, admin_id)
        result = connection.execute(
            """
            DELETE FROM usuarios
            WHERE id = ? AND nome_usuario != ? COLLATE NOCASE
            """,
            (user_id, ADMIN_USERNAME),
        )
        if result.rowcount == 0:
            raise ValueError("O utilizador não existe ou não pode ser apagado.")


def get_workouts(user_id: int) -> list[sqlite3.Row]:
    with database_connection() as connection:
        return connection.execute(
            """
            SELECT id, nome, divisao, data, notas
            FROM treinos
            WHERE usuario_id = ?
            ORDER BY id DESC
            """,
            (user_id,),
        ).fetchall()


def create_workout(
    user_id: int, name: str, division: str, notes: str
) -> None:
    with database_connection() as connection:
        connection.execute(
            """
            INSERT INTO treinos (usuario_id, nome, divisao, notas)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, name.strip(), division.strip(), notes.strip()),
        )


def delete_workout(workout_id: int, user_id: int) -> None:
    with database_connection() as connection:
        connection.execute(
            "DELETE FROM treinos WHERE id = ? AND usuario_id = ?",
            (workout_id, user_id),
        )


def get_exercises(workout_id: int, user_id: int) -> list[sqlite3.Row]:
    with database_connection() as connection:
        return connection.execute(
            """
            SELECT exercicios.id, exercicios.nome, exercicios.series,
                   exercicios.repeticoes, exercicios.descanso, exercicios.notas
            FROM exercicios
            JOIN treinos ON treinos.id = exercicios.treino_id
            WHERE exercicios.treino_id = ? AND treinos.usuario_id = ?
            ORDER BY exercicios.id
            """,
            (workout_id, user_id),
        ).fetchall()


def create_exercise(
    workout_id: int,
    user_id: int,
    name: str,
    sets: int,
    reps: str,
    rest_time: str,
) -> None:
    with database_connection() as connection:
        connection.execute(
            """
            INSERT INTO exercicios
                (treino_id, nome, series, repeticoes, descanso)
            SELECT ?, ?, ?, ?, ?
            WHERE EXISTS (
                SELECT 1 FROM treinos
                WHERE id = ? AND usuario_id = ?
            )
            """,
            (
                workout_id,
                name.strip(),
                sets,
                reps.strip(),
                rest_time.strip(),
                workout_id,
                user_id,
            ),
        )


def generate_smart_workout(focus: str, recovery: str) -> list[dict[str, str | int]]:
    workouts = {
        "Superiores": [
            ("Supino com halteres", 3, "8-12", 90),
            ("Remada sentada", 3, "8-12", 90),
            ("Puxada na frente", 3, "10-12", 75),
            ("Press de ombros na máquina", 2, "10-12", 75),
            ("Supino inclinado na máquina", 2, "10-12", 75),
        ],
        "Inferiores": [
            ("Leg press", 3, "8-12", 90),
            ("Peso morto romeno com halteres", 3, "8-12", 90),
            ("Agachamento goblet", 3, "10-12", 90),
            ("Hip thrust", 2, "10-12", 75),
            ("Subida para caixa (step-up)", 2, "10-12 por perna", 75),
        ],
        "Full body": [
            ("Leg press", 3, "8-12", 90),
            ("Supino com halteres", 3, "8-12", 90),
            ("Remada sentada", 3, "8-12", 90),
            ("Peso morto romeno com halteres", 2, "10-12", 90),
            ("Puxada na frente", 2, "10-12", 75),
        ],
    }
    exercises = workouts[focus]
    low_recovery = recovery == "Baixa (menos volume)"
    return [
        {
            "nome": name,
            "series": max(1, sets - 1) if low_recovery else sets,
            "repeticoes": reps,
            "descanso": f"{rest + 30 if low_recovery else rest}s",
        }
        for name, sets, reps, rest in exercises
    ]


def save_smart_workout(
    user_id: int,
    name: str,
    focus: str,
    recovery: str,
    exercises: list[dict[str, str | int]],
) -> None:
    notes = (
        "Sugestão geral para perfil de 85 kg e 30% de gordura corporal; "
        f"objetivo de perda de peso e recomposição corporal. Recuperação: {recovery}."
    )
    with database_connection() as connection:
        workout = connection.execute(
            """
            INSERT INTO treinos (usuario_id, nome, divisao, notas)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, name.strip(), focus, notes),
        )
        for exercise in exercises:
            connection.execute(
                """
                INSERT INTO exercicios
                    (treino_id, nome, series, repeticoes, descanso)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    workout.lastrowid,
                    exercise["nome"],
                    exercise["series"],
                    exercise["repeticoes"],
                    exercise["descanso"],
                ),
            )


def delete_exercise(exercise_id: int, workout_id: int, user_id: int) -> None:
    with database_connection() as connection:
        connection.execute(
            """
            DELETE FROM exercicios
            WHERE id = ? AND treino_id = ?
              AND EXISTS (
                  SELECT 1 FROM treinos
                  WHERE treinos.id = exercicios.treino_id
                    AND usuario_id = ?
              )
            """,
            (exercise_id, workout_id, user_id),
        )


def show_authentication_page() -> None:
    st.markdown(
        """
        <div class="brand-mark">🏋️‍♂️</div>
        <h1 class="auth-title">Meu Treino</h1>
        <p class="auth-subtitle">As tuas fichas de treino, sempre contigo.</p>
        """,
        unsafe_allow_html=True,
    )
    login_tab, register_tab = st.tabs(["Entrar", "Criar Conta"])

    with login_tab:
        with st.form("login_form"):
            username = st.text_input("Nome de utilizador")
            password = st.text_input("Palavra-passe", type="password")
            submitted = st.form_submit_button(
                "Entrar", type="primary", width="stretch"
            )
        if submitted:
            user = authenticate_user(username, password)
            if user is None:
                st.error("Nome de utilizador ou palavra-passe incorretos.")
            else:
                st.session_state.user = {
                    "id": user["id"],
                    "username": user["nome_usuario"],
                    "tipo": user["tipo"],
                }
                st.rerun()

    with register_tab:
        with st.form("register_form"):
            new_username = st.text_input("Nome de utilizador", key="new_username")
            new_password = st.text_input(
                "Palavra-passe (mínimo 8 caracteres)",
                type="password",
                key="new_password",
            )
            confirm_password = st.text_input(
                "Confirmar palavra-passe",
                type="password",
                key="confirm_password",
            )
            submitted = st.form_submit_button(
                "Criar conta", type="primary", width="stretch"
            )
        if submitted:
            if new_password != confirm_password:
                st.error("As palavras-passe não coincidem.")
            else:
                try:
                    register_user(new_username, new_password)
                except ValueError as error:
                    st.error(str(error))
                except sqlite3.IntegrityError:
                    st.error("Esse nome de utilizador já está em uso.")
                else:
                    user = authenticate_user(new_username, new_password)
                    if user is None:
                        st.error(
                            "A conta foi criada, mas não foi possível iniciar sessão."
                        )
                    else:
                        st.session_state.user = {
                            "id": user["id"],
                            "username": user["nome_usuario"],
                            "tipo": user["tipo"],
                        }
                        st.rerun()


def show_workout_cards(user_id: int) -> None:
    workouts = get_workouts(user_id)
    if not workouts:
        st.markdown(
            """
            <div class="empty-state">
                <div class="empty-icon">📋</div>
                <strong>Ainda não tens fichas</strong>
                <p>Cria a tua primeira ficha no separador “Criar Novo Treino”.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    workout = st.selectbox(
        "Ficha ativa",
        options=[item["id"] for item in workouts],
        format_func=lambda workout_id: next(
            (
                f"{item['nome']} · {item['divisao']}"
                if item["divisao"]
                else item["nome"]
            )
            for item in workouts
            if item["id"] == workout_id
        ),
        key=f"active_workout_{user_id}",
        label_visibility="collapsed",
    )
    workout_id = workout
    workout = next(item for item in workouts if item["id"] == workout_id)
    workout_name = html.escape(workout["nome"])
    workout_division = html.escape(workout["divisao"] or "Treino personalizado")
    st.markdown(
        f'<div class="workout-heading"><h2>{workout_name}</h2>'
        f'<span>{workout_division}</span></div>',
        unsafe_allow_html=True,
    )
    if workout["notas"]:
        st.caption(workout["notas"])

    exercises = get_exercises(workout_id, user_id)
    if not exercises:
        st.info("Esta ficha ainda não tem exercícios. Adiciona o primeiro abaixo.")
    else:
        for exercise in exercises:
            with st.container(border=True):
                card, delete = st.columns([5, 1], vertical_alignment="center")
                with card:
                    st.markdown(f"**{exercise['nome']}**")
                    st.caption(
                        f"{exercise['series']} séries  ·  "
                        f"{exercise['repeticoes']} repetições  ·  "
                        f"{exercise['descanso']} de descanso"
                    )
                    if exercise["notas"]:
                        st.caption(exercise["notas"])
                with delete:
                    if st.button(
                        "🗑️",
                        key=f"delete_exercise_{exercise['id']}",
                        help="Apagar exercício",
                        width="stretch",
                    ):
                        delete_exercise(exercise["id"], workout_id, user_id)
                        st.rerun()

    with st.expander("➕ Adicionar exercício", expanded=not exercises):
        with st.form(f"add_exercise_{workout_id}"):
            name = st.text_input("Nome do exercício", placeholder="Ex.: Supino reto")
            sets = st.number_input("Séries", min_value=1, value=3, step=1)
            reps = st.text_input(
                "Repetições",
                value="8-12",
                help="Podes indicar um intervalo, por exemplo 8-12.",
            )
            rest_time = st.text_input(
                "Tempo de descanso",
                value="60s",
                help="Indica a duração, por exemplo 60s ou 1min.",
            )
            submitted = st.form_submit_button(
                "Adicionar exercício", type="primary", width="stretch"
            )
        if submitted:
            if not name.strip() or not reps.strip() or not rest_time.strip():
                st.error(
                    "Preenche o nome, as repetições e o tempo de descanso."
                )
            else:
                create_exercise(
                    workout_id, user_id, name, int(sets), reps, rest_time
                )
                st.rerun()

    st.markdown("")
    if st.button(
        "🗑️ Apagar esta ficha de treino",
        key=f"delete_workout_{workout_id}",
        width="stretch",
    ):
        delete_workout(workout_id, user_id)
        st.session_state.pop(f"active_workout_{user_id}", None)
        st.rerun()


def show_create_workout_form(user_id: int) -> None:
    st.subheader("Criar uma ficha")
    st.caption("Organiza os exercícios por objetivo ou grupo muscular.")
    with st.form("create_workout_form"):
        name = st.text_input("Nome do treino", placeholder="Ex.: Treino A")
        division = st.selectbox(
            "Divisão / foco muscular",
            [
                "Peito / Tríceps",
                "Costas / Bíceps",
                "Pernas",
                "Ombros",
                "Full body",
                "Outro",
            ],
        )
        if division == "Outro":
            division = st.text_input(
                "Indica a divisão muscular", placeholder="Ex.: Peito e ombros"
            )
        notes = st.text_area("Notas (opcional)")
        submitted = st.form_submit_button(
            "Criar ficha de treino", type="primary", width="stretch"
        )
    if submitted:
        if not name.strip() or not division.strip():
            st.error("Preenche o nome e a divisão muscular do treino.")
        else:
            create_workout(user_id, name, division, notes)
            st.success("Ficha de treino criada.")
            st.rerun()


def show_smart_workout_generator(user_id: int) -> None:
    st.subheader("Gerar Treino Inteligente")
    st.caption(
        "Sugestões para o perfil indicado: 85 kg, 30% de gordura corporal, "
        "com foco em perda de peso e recomposição corporal."
    )
    st.info(
        "A seleção prioriza movimentos multiarticulares e um volume moderado. "
        "O peso e a percentagem de gordura, por si só, não determinam as cargas: "
        "escolhe uma carga que permita executar cada repetição com boa técnica."
    )
    focus = st.selectbox(
        "Foco do dia",
        ["Superiores", "Inferiores", "Full body"],
        key=f"smart_focus_{user_id}",
    )
    recovery = st.selectbox(
        "Como está a tua recuperação?",
        ["Normal", "Baixa (menos volume)"],
        help=(
            "Se ainda sentes fadiga do treino anterior, escolhe recuperação baixa "
            "para reduzir séries e aumentar o descanso."
        ),
        key=f"smart_recovery_{user_id}",
    )
    if st.button(
        "🤖 Gerar Treino Inteligente",
        type="primary",
        key=f"generate_smart_workout_{user_id}",
        width="stretch",
    ):
        st.session_state[f"smart_workout_{user_id}"] = {
            "focus": focus,
            "recovery": recovery,
            "exercises": generate_smart_workout(focus, recovery),
        }

    suggestion = st.session_state.get(f"smart_workout_{user_id}")
    if not suggestion:
        return
    st.markdown(f"#### Sugestão: {suggestion['focus']}")
    st.caption(
        "Mantém 1–3 repetições em reserva e descansa o suficiente para "
        "preservar a técnica. Ajusta ou interrompe qualquer movimento que cause dor."
    )
    for exercise in suggestion["exercises"]:
        with st.container(border=True):
            st.markdown(f"**{exercise['nome']}**")
            st.caption(
                f"{exercise['series']} séries · {exercise['repeticoes']} repetições "
                f"· {exercise['descanso']} de descanso"
            )

    workout_name = st.text_input(
        "Nome da ficha",
        value=f"Treino Inteligente - {suggestion['focus']}",
        key=f"smart_workout_name_{user_id}",
    )
    if st.button(
        "Guardar nas minhas fichas",
        key=f"save_smart_workout_{user_id}",
        width="stretch",
    ):
        if not workout_name.strip():
            st.error("Indica um nome para a ficha.")
        else:
            save_smart_workout(
                user_id,
                workout_name,
                suggestion["focus"],
                suggestion["recovery"],
                suggestion["exercises"],
            )
            st.success("Treino inteligente guardado nas tuas fichas.")


def show_admin_panel(admin_id: int) -> None:
    st.title("🛡️ Painel do Administrador")
    st.caption("Gestão das contas e visão geral dos treinos.")
    users_tab, overview_tab = st.tabs(
        ["👥 Utilizadores", "📊 Visão geral dos treinos"]
    )

    with users_tab:
        users = get_admin_users(admin_id)
        st.subheader("Contas registadas")
        st.dataframe(
            [
                {
                    "Utilizador": user["nome_usuario"],
                    "Tipo de conta": user["tipo"],
                    "Treinos": user["total_treinos"],
                }
                for user in users
            ],
            width="stretch",
            hide_index=True,
        )

        deletable_users = [user for user in users if user["id"] != admin_id]
        if not deletable_users:
            st.info("Não existem outras contas para gerir.")
        else:
            st.markdown("#### Apagar utilizador")
            selected_user = st.selectbox(
                "Seleciona a conta",
                options=[user["id"] for user in deletable_users],
                format_func=lambda user_id: next(
                    user["nome_usuario"]
                    for user in deletable_users
                    if user["id"] == user_id
                ),
                key="admin_selected_user",
            )
            selected_user = next(
                user for user in deletable_users if user["id"] == selected_user
            )
            confirmed = st.checkbox(
                f"Confirmo que quero apagar a conta "
                f"“{selected_user['nome_usuario']}” e os respetivos treinos.",
                key=f"confirm_delete_user_{selected_user['id']}",
            )
            if st.button(
                "🗑️ Apagar utilizador",
                type="primary",
                disabled=not confirmed,
                key=f"admin_delete_user_{selected_user['id']}",
                width="stretch",
            ):
                delete_user_account(admin_id, selected_user["id"])
                st.success("Utilizador e respetivos treinos apagados.")
                st.rerun()

    with overview_tab:
        workouts = get_admin_workouts(admin_id)
        total_users = len(users)
        total_exercises = sum(
            workout["total_exercicios"] for workout in workouts
        )
        metric_users, metric_workouts, metric_exercises = st.columns(3)
        metric_users.metric("Utilizadores", total_users)
        metric_workouts.metric("Treinos", len(workouts))
        metric_exercises.metric("Exercícios", total_exercises)

        if workouts:
            st.dataframe(
                [
                    {
                        "Utilizador": workout["nome_usuario"],
                        "Treino": workout["nome"],
                        "Divisão / foco": workout["divisao"],
                        "Data": workout["data"],
                        "Exercícios": workout["total_exercicios"],
                    }
                    for workout in workouts
                ],
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("Ainda não existem treinos registados.")


st.set_page_config(page_title="Meu Treino", page_icon="🏋️‍♂️", layout="centered")
st.markdown(
    """
    <style>
    .block-container {
        max-width: 760px;
        padding-top: 1.5rem;
        padding-bottom: 3rem;
    }
    [data-testid="stSidebar"] { min-width: 250px; }
    .brand-mark { text-align: center; font-size: 3rem; margin-top: 1rem; }
    .auth-title { text-align: center; margin: 0; }
    .auth-subtitle { text-align: center; color: #8b95a1; margin: 0 0 1.5rem; }
    .workout-heading { margin: 1.25rem 0 1rem; }
    .workout-heading h2 { margin: 0; }
    .workout-heading span { color: #8b95a1; font-size: 0.95rem; }
    .empty-state {
        border: 1px dashed rgba(128, 128, 128, 0.45);
        border-radius: 16px;
        padding: 2rem 1rem;
        text-align: center;
        margin: 1.5rem 0;
    }
    .empty-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
    .empty-state p { color: #8b95a1; margin-bottom: 0; }
    div.stButton > button, div.stFormSubmitButton > button {
        min-height: 2.8rem;
        border-radius: 10px;
    }
    @media (max-width: 640px) {
        .block-container { padding: 1rem 1rem 2rem; }
        [data-testid="stSidebar"] { min-width: 0; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

admin_ready = init_db()
if not admin_ready:
    st.warning(
        "A conta administradora JJadm ainda não foi criada. "
        "Define MEU_TREINO_ADMIN_PASSWORD ou o segredo `admin_password` "
        "no Streamlit para a inicializar."
    )

if "user" in st.session_state:
    session_user = get_session_user(st.session_state.user["id"])
    if session_user is None:
        st.session_state.pop("user", None)
        st.rerun()
    st.session_state.user = {
        "id": session_user["id"],
        "username": session_user["nome_usuario"],
        "tipo": session_user["tipo"],
    }

if "user" not in st.session_state:
    show_authentication_page()
else:
    current_user = st.session_state.user
    st.sidebar.markdown("### 🏋️‍♂️ Meu Treino")
    st.sidebar.write(f"Conta: **{current_user['username']}**")
    if st.sidebar.button("Sair da Conta", width="stretch"):
        st.session_state.pop("user", None)
        st.rerun()

    if (
        current_user["tipo"] == "admin"
        and current_user["username"].casefold() == ADMIN_USERNAME.casefold()
    ):
        show_admin_panel(current_user["id"])
    else:
        st.title("🏋️‍♂️ Meu Treino")
        ficha_tab, create_tab, smart_tab = st.tabs(
            [
                "📋 Fichas de Treino",
                "➕ Criar Novo Treino",
                "🤖 Treino Inteligente",
            ]
        )
        with ficha_tab:
            show_workout_cards(current_user["id"])
        with create_tab:
            show_create_workout_form(current_user["id"])
        with smart_tab:
            show_smart_workout_generator(current_user["id"])
