import ldap
import os
import sys
import tempfile
from ldap import LDAPError, modlist
from ldap.ldapobject import LDAPObject
from typing import Final, TextIO
from pypomes_core.env_pomes import APP_PREFIX, env_get_str, env_get_int
from pypomes_core.exception_pomes import exc_format

_val: str = env_get_str(f"{APP_PREFIX}_LDAP_BASE_DN")
LDAP_BASE_DN: Final[str] = None if _val is None else _val.replace(":", "=")
_val = env_get_str(f"{APP_PREFIX}_LDAP_BIND_DN")
LDAP_BIND_DN:  Final[str] = None if _val is None else _val.replace(":", "=")
LDAP_BIND_PWD:  Final[str] = env_get_str(f"{APP_PREFIX}_LDAP_BIND_PWD")
LDAP_SERVER_URI:  Final[str] = env_get_str(f"{APP_PREFIX}_LDAP_SERVER_URI")
LDAP_TIMEOUT:  Final[int] = env_get_int(f"{APP_PREFIX}_LDAP_TIMEOUT", 30)
LDAP_TRACE_FILE:  Final[str] = env_get_str(f"{APP_PREFIX}_LDAP_TRACE_FILEPATH",
                                           os.path.join(tempfile.gettempdir(), f"{APP_PREFIX}_ldap.log"))
LDAP_TRACE_LEVEL:  Final[int] = env_get_int(f"{APP_PREFIX}_LDAP_TRACE_LEVEL", 0)


def ldap_init(errors: list[str], server_uri: str = LDAP_SERVER_URI,
              trace_filepath: str = LDAP_TRACE_FILE, trace_level: int = LDAP_TRACE_LEVEL) -> LDAPObject:

    # inicializa a variável de retorno
    result: LDAPObject | None = None

    try:
        # abre dispositivo de saída para trace
        trace_out: TextIO
        match trace_filepath:
            case "sys.stdout" | None:
                trace_out = sys.stdout
            case "sys.stderr":
                trace_out = sys.stderr
            case _:
                trace_out = open(trace_filepath, "a")

        if not isinstance(trace_level, int):
            trace_level = 0

        # obtem a conexão
        result = ldap.initialize(uri=server_uri,
                                 trace_level=trace_level,
                                 trace_file=trace_out)
        # configura a conexão
        result.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        result.set_option(ldap.OPT_REFERRALS, 0)
        result.set_option(ldap.OPT_TIMEOUT, LDAP_TIMEOUT)
    except Exception as e:
        errors.append(f"Erro na inicialização do cliente LDAP: {__ldap_except_msg(e)}")

    return result


def ldap_bind(errors: list[str], conn: LDAPObject,
              bind_dn: str = LDAP_BIND_DN, bind_pwd: str = LDAP_BIND_PWD) -> bool:

    # inicializa a variável de retorno
    result: bool = False

    # faz o enlace
    try:
        conn.simple_bind_s(who=bind_dn,
                           cred=bind_pwd)
        result = True
    except Exception as e:
        errors.append(f"Erro no enlace com o servidor LDAP: {__ldap_except_msg(e)}")

    return result


def ldap_unbind(errors: list[str], conn: LDAPObject):

    try:
        conn.unbind_s()
        # o dispositivo de saída do trace é stdout ou stderr ?
        # noinspection PyProtectedMember
        if conn._trace_file.name not in ["<stdout>", "<stderr>"]:
            # não, feche o dispositivo
            # noinspection PyProtectedMember
            conn._trace_file.close()
    except Exception as e:
        errors.append(f"Erro ao desfazer o enlace com o servidor LDAP: {__ldap_except_msg(e)}")


def ldap_add_entry(errors: list[str], entry_dn: str, attrs: dict):

    # inicializa o serviço LDAP
    conn: LDAPObject = ldap_init(errors)

    bound: bool = False
    # a conexão foi inicializada ?
    if conn is not None:
        # sim, faça o enlace com o servidor LDAP
        bound = ldap_bind(errors, conn)

    # houve erros ?
    if len(errors) == 0:
        # não, prossiga
        ldiff: list[tuple[any, any]] = modlist.addModlist(attrs)
        try:
            conn.add_s(dn=entry_dn,
                       modlist=ldiff)
        except Exception as e:
            errors.append(f"Erro na operação ldap_add_entry: {__ldap_except_msg(e)}")

    # desfaz o enlace com o servidor LDAP, se necessário
    if bound:
        ldap_unbind(errors, conn)


def ldap_modify_entry(errors: list[str], entry_dn: str, mod_entry: list[tuple[int, str, any]]):

    # inicializa o serviço LDAP
    conn: LDAPObject = ldap_init(errors)

    bound: bool = False
    # a conexão foi inicializada ?
    if conn is not None:
        # sim, faça o enlace com o servidor LDAP
        bound = ldap_bind(errors, conn)

    # houve erros ?
    if len(errors) == 0:
        # não, prossiga
        try:
            conn.modify_s(dn=entry_dn,
                          modlist=mod_entry)
        except Exception as e:
            errors.append(f"Erro na operação ldap_modify_entry: {__ldap_except_msg(e)}")

    # desfaz o enlace com o servidor LDAP, se necessário
    if bound:
        ldap_unbind(errors, conn)


def ldap_delete_entry(errors: list[str], entry_dn: str):

    # inicializa o serviço LDAP
    conn: LDAPObject = ldap_init(errors)

    bound: bool = False
    # a conexão foi inicializada ?
    if conn is not None:
        # sim, faça o enlace com o servidor LDAP
        bound = ldap_bind(errors, conn)

    # houve erros ?
    if len(errors) == 0:
        # não, prossiga
        try:
            conn.delete_s(dn=entry_dn)
        except Exception as e:
            errors.append(f"Erro na operação ldap_delete_entry: {__ldap_except_msg(e)}")

    # desfaz o enlace com o servidor LDAP, se necessário
    if bound:
        ldap_unbind(errors, conn)


def ldap_modify_user(errors: list[str], user_id: str, attrs: list[tuple[str, bytes | None]]):

    # invoque a operação de consulta
    search_data: list[tuple[str, dict]] = ldap_search(errors, f"cn=users,{LDAP_BASE_DN}",
                                                      [attr[0] for attr in attrs],
                                                      ldap.SCOPE_ONELEVEL, f"cn={user_id}")

    # a consulta retornou dados ?
    if search_data is None or len(search_data) == 0:
        # não, reporte o erro
        errors.append(f"Erro na operação ldap_modify_user: Usuário '{user_id}' não encontrado")

    # houve erros ?
    if len(errors) == 0:
        # não, prossiga
        entry_dn: str = search_data[0][0]

        # constrói a lista de modificações
        mod_entries: list[tuple[int, str, bytes | None]] = []
        for attr_name, new_value in attrs:
            entry_list: list[bytes] = search_data[0][1].get(attr_name)
            if new_value is not None:
                curr_value: bytes = None if entry_list is None else entry_list[0]
                # avalia se os valores atual e novo são distintos
                if new_value != curr_value:
                    # define o modo de atualização
                    if curr_value is None:
                        mode: int = ldap.MOD_ADD
                    else:
                        mode: int = ldap.MOD_REPLACE
                    mod_entries.append((mode, attr_name, new_value))
            elif entry_list is not None:
                mod_entries.append((ldap.MOD_DELETE, attr_name, None))

        # há atributos a serem modificados ?
        if len(mod_entries) > 0:
            # sim, modifique-os
            ldap_modify_entry(errors, entry_dn, mod_entries)


def ldap_change_pwd(errors: list[str], user_dn: str, new_pwd: str, curr_pwd: str | None = None) -> str:

    # inicializa a variável de retorno
    result: str | None = None

    # inicializa o serviço LDAP
    conn: LDAPObject = ldap_init(errors)

    bound: bool = False
    # faça o enlace com o servidor LDAP, se a conexão foi inicializada
    if conn is not None:
        # a senha associada ao DN foi especificada ?
        if curr_pwd is None:
            # não, faça o enlace padrão
            bound = ldap_bind(errors, conn)
        else:
            # sim, faça o enlace com o DN fornecido
            bound = ldap_bind(errors, conn, user_dn, curr_pwd)

    # houve erros ?
    if len(errors) == 0:
        try:
            # a conexão é segura ?
            if __is_secure(conn):
                # sim, use a diretiva 'passwd_s'
                resp: tuple[None, bytes] = conn.passwd_s(user=user_dn,
                                                         oldpw=curr_pwd,
                                                         newpw=new_pwd,
                                                         extract_newpw=True)
                result = resp[1].decode()
            else:
                # não, use a diretiva 'modify_s'
                conn.modify_s(dn=user_dn,
                              modlist=[(ldap.MOD_REPLACE, "userpassword", new_pwd.encode())])
                result = new_pwd
        except Exception as e:
            errors.append(f"Erro na operação ldap_change_pwd: {__ldap_except_msg(e)}")

    # desfaz o enlace com o servidor LDAP, se necessário
    if bound:
        ldap_unbind(errors, conn)

    return result


def ldap_search(errors: list[str], base_dn: str,  attrs: list[str],
                scope: str = None, filter_str: str = None, attrs_only: bool = False) -> list[tuple[str, dict]]:

    # inicializa a variável de retorno
    result:  list[tuple[str, dict]] | None = None

    # inicializa o serviço LDAP
    conn: LDAPObject = ldap_init(errors)

    bound: bool = False
    # a conexão foi inicializada ?
    if conn is not None:
        # sim, faça o enlace com o servidor LDAP
        bound = ldap_bind(errors, conn)

    # houve erros ?
    if len(errors) == 0:
        # não, prossiga (se attrs_only for especificado, os valores dos atributos não são retornados)
        attr_vals: int = 1 if attrs_only else 0
        try:
            result = conn.search_s(base=base_dn,
                                   scope=scope or ldap.SCOPE_BASE,
                                   filterstr=filter_str or "(objectClass=*)",
                                   attrlist=attrs,
                                   attrsonly=attr_vals)
        except Exception as e:
            errors.append(f"Erro na operação ldap_search: {__ldap_except_msg(e)}")

    # desfaz o enlace com o servidor LDAP, se necessário
    if bound:
        ldap_unbind(errors, conn)

    return result


def ldap_get_value(errors: list[str], entry_dn: str, attr: str) -> bytes:

    data: list[bytes] = ldap_get_value_list(errors, entry_dn, attr)
    result: bytes = data[0] if isinstance(data, list) and len(data) > 0 else None

    return result


def ldap_add_value(errors: list[str], entry_dn: str, attr: str, value: bytes):

    mod_entries: list[tuple[int, str, bytes]] = [(ldap.MOD_ADD, attr, value)]
    ldap_modify_entry(errors, entry_dn, mod_entries)


def ldap_set_value(errors: list[str], entry_dn: str, attr: str, value: bytes | None):

    # obtem o valor atual
    curr_value: bytes = ldap_get_value(errors, entry_dn, attr)

    # houve erros ?
    if len(errors) == 0:
        # não, defina o modo de atualização da estrutura LDAP
        mode: int | None = None
        if curr_value is None:
            if value is not None:
                mode = ldap.MOD_ADD
        elif value is None:
            mode = ldap.MOD_DELETE
        elif curr_value != value:
            mode = ldap.MOD_REPLACE

        # o modo de atualização da estrutura LDAP foi definido ?
        if mode is not None:
            # sim, atualize-a
            mod_entries: list[tuple[int, str, bytes]] = [(mode, attr, value)]
            ldap_modify_entry(errors, entry_dn, mod_entries)


def ldap_get_value_list(errors: list[str], entry_dn: str, attr: str) -> list[bytes]:

    # inicializa variável de retorno
    result: list[bytes] | None = None

    # executa a consulta
    search_data: list[tuple[str, dict]] = ldap_search(errors, entry_dn, [attr])

    # a consulta retornou dados ?
    if isinstance(search_data, list) and len(search_data) > 0:
        # sim, prossiga
        user_data: dict = search_data[0][1]
        result = user_data.get(attr)

    return result


def ldap_get_values(errors: list[str], entry_dn: str, attrs: list[str]) -> tuple[bytes]:

    # inicializa variável de retorno
    result: tuple[bytes] | None = None

    # executa a consulta
    search_data: tuple[list[bytes | None] | None] = ldap_get_values_lists(errors, entry_dn, attrs)

    # a consulta retornou dados ?
    if isinstance(search_data, tuple):
        # sim, prossiga
        search_items: list[bytes] = [item if item is None else item[0] for item in search_data]
        result = tuple(search_items)

    return result


def ldap_get_values_lists(errors: list[str], entry_dn: str, attrs: list[str]) -> tuple[list[bytes]]:

    # inicializa variável de retorno
    result: tuple[list[bytes]] | None = None

    # executa a consulta
    search_data: list[tuple[str, dict]] = ldap_search(errors, entry_dn, attrs)

    # a consulta retornou dados ?
    if isinstance(search_data, list) and len(search_data) > 0:
        # sim, prossiga
        user_data: dict = search_data[0][1]
        items: list[list[bytes]] = []
        for attr in attrs:
            items.append(user_data.get(attr))
        result = tuple(items)

    return result


def __is_secure(conn: LDAPObject) -> bool:

    # noinspection PyProtectedMember
    return conn._uri.startswith("ldaps:")


# constrói a mensagem de erro a partir da exceção produzida
def __ldap_except_msg(exc: Exception) -> str:

    if isinstance(exc, LDAPError):
        err_data: any = exc.args[0]
        # type(exc) -> <class '<nome-da-classe'>
        cls: str = f"{type(exc)}"[8:-2]
        result: str = f"'Type: {cls}; Code: {err_data.get('result')}; Msg: {err_data.get('desc')}'"
        info: str = err_data.get("info")
        if info is not None:
            result = f"{result[:-1]}; Info: {info}'"
    else:
        result: str = exc_format(exc, sys.exc_info())

    return result
