# guacamole-mcp-server

Servidor MCP que permite ao Claude Code executar comandos em servidores acessíveis pelo
**Apache Guacamole**: Linux via conexões **SSH** e Windows via conexões **RDP com WinRM**
(extensão **guacamole-winrm**). Também consulta e administra o próprio Guacamole (conexões,
grupos, usuários e permissões), no limite das permissões do usuário configurado. Basta pedir:

> Analise o servidor `web-server-01` para ver por que o nginx está retornando 502

e o Claude encontra a conexão no Guacamole, executa os comandos através dele e investiga. Ou:

> Dê acesso de leitura ao usuário `joao` em todas as conexões do grupo `Clientes/Linux/24410 - ACME`

## Como funciona — SSH (Linux)

Tudo passa pelo Guacamole — a máquina onde o MCP roda **não precisa** alcançar os servidores
via SSH nem conhecer as credenciais deles; basta acessar a interface web do Guacamole.

1. Autentica na API REST (`/api/tokens`) e lista as conexões da árvore de cada *data source*.
2. Abre o túnel WebSocket (`/websocket-tunnel`), igual ao navegador faz.
3. Envia o comando para o terminal por um *pipe stream* de entrada chamado `STDIN`
   (mesmo mecanismo do `guacctl`).
4. Captura a saída com as sequências OSC privadas do terminal do guacd
   (`ESC]482202;…` abre um *pipe stream* de saída, `ESC]482203;` fecha). O comando é
   enviado em base64 e envolvido assim:

   ```sh
    printf '\033]482202;2;guac-mcp-<id>\007'; eval "$(printf %s <base64> | base64 -d)" </dev/null 2>&1; printf '\n<marcador-rc>%s\n' "$?"; printf '\033]482203;\007'
   ```

   Assim a saída chega como texto (stdout+stderr) junto com o *exit code*, em vez de pixels.

A sessão SSH fica aberta entre chamadas (`cd` e variáveis persistem) e é fechada após
inatividade.

## Como funciona — WinRM (Windows)

Conexões RDP com **Habilitar WinRM** marcado (atributo `winrm-enabled=true`) usam o endpoint
da extensão `guacamole-winrm`:
`POST /api/session/ext/{dataSource}/connections/{id}/execute` com `{command, cwd}`, que retorna
`{stdout, stderr, exitCode, cwd}`. Host e credenciais ficam dentro do Guacamole.

- Os comandos são **PowerShell** (`list_connections` informa `"shell": "powershell"`).
- **Cada chamada é um processo PowerShell novo**: só o diretório atual persiste (o MCP reenvia o
  `cwd` retornado); variáveis, funções e módulos se perdem. As instruções do MCP avisam o Claude
  para juntar passos dependentes no mesmo comando.
- A saída só chega no fim. Se passar de `timeout_seconds`, o MCP desiste de esperar, mas o
  comando **continua rodando** no Windows (a extensão não permite cancelar).
- Requer a versão da extensão que executa o comando como script block com dot-source e
  saída em UTF-8; versões anteriores descartavam erros não-terminantes e corrompiam acentos.
- O usuário do Guacamole usado pelo MCP precisa de permissão de **edição** na conexão RDP
  (sem ela a extensão não revela o host).

## Ferramentas expostas

| Ferramenta | Descrição |
|---|---|
| `list_connections(search?, include_all?)` | Lista conexões SSH e RDP com WinRM (nome, id, grupo, data source, `shell`) |
| `run_command(connection, command, timeout_seconds?, shell?)` | Executa um comando e retorna saída + exit code. `connection` aceita nome exato, parte única do nome, `grupo/nome` ou identificador. `shell` (`posix`/`powershell`) declara a linguagem do comando: se não bater com a conexão, nada é executado — é o que permite a um hook de segurança classificar o comando com a gramática certa |
| `list_sessions()` | Sessões abertas pelo MCP |
| `close_session(connection)` | Fecha a sessão de uma conexão |

Em timeout, no SSH o comando recebe Ctrl+C e a saída parcial é retornada; no WinRM, veja acima.

### Administração do Guacamole

As ferramentas abaixo usam a API REST (`/api/session/data/{dataSource}/...`) **como o usuário
configurado**. Quem decide o que é permitido é o próprio Guacamole: permissões de sistema
(`ADMINISTER`, `CREATE_USER`, `CREATE_CONNECTION`...) e `UPDATE`/`DELETE`/`ADMINISTER` em cada
objeto. O que o usuário não pode fazer volta como erro HTTP 403 com o nome do usuário. O mesmo
servidor atende um usuário só de leitura e um administrador; `get_current_user` mostra as
permissões.

| Ferramenta | Descrição |
|---|---|
| `get_current_user()` | Usuário do MCP, grupos, permissões de sistema e em quantos objetos tem cada permissão |
| `get_connection(connection, history_limit?)` | Protocolo, grupo, parâmetros (hostname, porta, usuário...), atributos e últimas sessões. Parâmetros exigem `UPDATE` na conexão |
| `list_connection_groups(search?)` | Grupos de conexão com caminho, id, tipo e quantidade de filhos |
| `list_active_connections(search?)` | Sessões abertas agora: conexão, usuário, IP de origem, início |
| `list_users(search?)` / `get_user(username, history_limit?, include_effective?)` | Usuários; detalhe com grupos, permissões (ids viram nomes), permissões efetivas e últimos logins |
| `list_user_groups(search?)` / `get_user_group(group)` | Grupos de usuários; detalhe com membros, grupos pais e permissões |
| `create_connection` / `update_connection` / `delete_connection` | Cria, renomeia, move (`group`) ou altera parâmetros e atributos de uma conexão |
| `create_connection_group` / `update_connection_group` / `delete_connection_group` | Pastas de conexões. Grupo com conteúdo não é apagado (o Guacamole apagaria tudo dentro) |
| `create_user` / `update_user` / `delete_user` | Usuários: senha, ativar/desativar (`disabled`), atributos (nome, e-mail, validade...) |
| `create_user_group` / `update_user_group` / `delete_user_group` | Grupos de usuários |
| `update_group_members(group, add_users?, remove_users?, add_groups?, remove_groups?)` | Membros de um grupo; `not_applied` lista o que o Guacamole ignorou (nome inexistente) |
| `update_permissions(target_type, target?, grant?, revoke?, user? \| user_group?)` | Concede ou revoga permissões em conexão, grupo de conexão, usuário, grupo de usuários ou de sistema |

- **Alterações mesclam.** O `PUT` do Guacamole substitui o objeto inteiro (parâmetros, atributos,
  `disabled`); o MCP lê o objeto atual e muda só os campos informados. `null` limpa um parâmetro
  ou atributo; booleanos viram `"true"`/vazio, como o Guacamole grava.
- **Nome exato nas alterações.** Leitura aceita parte única do nome; alteração exige nome exato,
  `grupo/nome` ou identificador (conexão) e caminho, nome ou identificador (grupo de conexão).
- **Segredos mascarados.** Senhas, chaves privadas, passphrases, segredo de TOTP e configuração do
  Keeper aparecem como `***`. Um valor `***` numa alteração é recusado (é a máscara, não o valor).
- **Sessões.** Alterar ou apagar uma conexão fecha a sessão aberta nela pelo MCP; o próximo
  `run_command` já usa a configuração nova.
- **Proteções.** O MCP não apaga nem desativa o próprio usuário e não move um grupo para dentro
  dele mesmo.
- **Data source.** Usuários, grupos e conexões novas ficam no primeiro de
  `GUACAMOLE_DATA_SOURCES` ou, sem ele, no data source que autenticou o usuário (`mysql` numa
  instalação com banco). Com LDAP + MySQL, defina `GUACAMOLE_DATA_SOURCES=mysql`.
- **Sem padrões automáticos.** `create_connection` não acrescenta parâmetros (gravação de sessão,
  drive, typescript): passe os que o padrão da equipe exige.
- Compatível com Guacamole 1.6 (`disabled` como propriedade) e anteriores (`disabled` como
  atributo).

## Instalação

Requer apenas o [uv](https://docs.astral.sh/uv/getting-started/installation/) — não é preciso
clonar o repositório. O `uvx` baixa o código do Git, cria um ambiente isolado em cache (e
instala o Python 3.12 se faltar) e executa o servidor localmente, com as **suas** credenciais
do Guacamole.

```sh
claude mcp add guacamole \
  -e GUACAMOLE_URL=https://guacamole.exemplo.com.br/guacamole \
  -e GUACAMOLE_USERNAME=seu.usuario \
  -e GUACAMOLE_PASSWORD='sua-senha' \
  -- uvx --from git+https://github.com/lsgalves/guacamole-mcp-server@v0.2.0 guacamole-mcp-server
```

Ou em `.mcp.json` (veja `.mcp.json.example`). Evite versionar a senha: use
`"GUACAMOLE_PASSWORD": "${GUACAMOLE_PASSWORD}"` e exporte a variável no shell.

- **Repositório privado:** o `uv` usa as credenciais do Git da sua máquina. Com chave SSH, use
  `git+ssh://git@github.com/lsgalves/guacamole-mcp-server.git@v0.2.0`.
- **Versões:** o sufixo `@v0.2.0` fixa uma tag. Para atualizar, troque a tag na configuração.
  Sem tag, o `uvx` usa a branch padrão e mantém em cache a versão baixada; rode
  `uvx --refresh --from git+... guacamole-mcp-server` para buscar a mais recente.

### Desenvolvimento

Para rodar a partir de um clone local (alterações no código valem na hora):

```sh
claude mcp add guacamole -e ... -- uv run --project /caminho/para/guacamole-mcp-server guacamole-mcp-server
```

### Publicar uma nova versão

Atualize `version` em `pyproject.toml`, faça commit e crie a tag correspondente:

```sh
git tag v0.2.0 && git push origin v0.2.0
```

### Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `GUACAMOLE_URL` | — | URL base, incluindo o contexto (ex.: `https://host/guacamole`) |
| `GUACAMOLE_USERNAME` / `GUACAMOLE_PASSWORD` | — | Usuário do Guacamole |
| `GUACAMOLE_VERIFY_SSL` | `true` | `false` para certificados autoassinados |
| `GUACAMOLE_DATA_SOURCES` | todas | Ex.: `mysql,ldap` para restringir |
| `GUACAMOLE_COMMAND_TIMEOUT` | `60` | Timeout padrão por comando (s) |
| `GUACAMOLE_SESSION_IDLE_TIMEOUT` | `900` | Fecha sessões ociosas após N s |
| `GUACAMOLE_LOG_LEVEL` | `WARNING` | Log em stderr |
| `MCP_TRANSPORT` | `stdio` | `http` para servir via Streamable HTTP (veja abaixo) |
| `MCP_HOST` / `MCP_PORT` | `127.0.0.1` / `8000` | Endereço do modo HTTP (endpoint em `/mcp`) |
| `MCP_ALLOWED_HOSTS` | — | Hosts aceitos no cabeçalho `Host` (ex.: `mcp.exemplo.com.br`); ativa a proteção contra DNS rebinding |

## Servidor central via HTTP / Docker (preparado, ainda não recomendado)

O modo HTTP permite rodar um único servidor para toda a equipe:

```sh
cp .env.example .env   # preencha GUACAMOLE_* e MCP_ALLOWED_HOSTS
docker compose up -d --build
```

O container escuta só no loopback do host (`127.0.0.1:8000`); publique por um proxy reverso
com HTTPS. Cada pessoa configura assim:

```sh
claude mcp add --transport http guacamole https://mcp-guacamole.exemplo.com.br/mcp
```

> **Atenção — antes de usar em produção:**
> - O endpoint **não tem autenticação**: qualquer pessoa que alcance a URL executa comandos
>   em todos os servidores a que o usuário do Guacamole tem acesso.
> - Todos os clientes usam o **mesmo usuário do Guacamole** (a auditoria não identifica quem
>   executou o comando) e **compartilham as sessões SSH** (`cd`/variáveis de um afetam os outros).
> - As sessões ficam em memória: rode uma única réplica.
>
> Para uso real, falta autenticação por usuário (credenciais ou token do Guacamole por
> requisição, ou OAuth/SSO) com sessões separadas por usuário.

## Requisitos e limitações (SSH)

- As credenciais SSH precisam estar **salvas na conexão** do Guacamole (sem prompt interativo
  de login) e a conexão não pode ser *read-only*.
- O shell remoto deve ser POSIX (bash, sh, zsh, dash, ash) com `base64` e `printf`.
- guacd ≥ 1.1 (testado com guacamole/guacd **1.6.0**).
- Usuários com 2FA (TOTP/Duo) no Guacamole não são suportados — use um usuário de serviço.
- Comandos não podem ser interativos (stdin é `/dev/null`); use `--no-pager`, `top -b -n 1`, etc.
- Saída limitada a 200 KB por comando.
- Os comandos aparecem nas gravações de sessão (*session recording*) do Guacamole, se habilitadas.

## Segurança

O Claude Code pede confirmação antes de cada `run_command`, a menos que você libere a ferramenta
(`mcp__guacamole__run_command`) nas permissões. Use um usuário do Guacamole com acesso apenas às
conexões necessárias e, idealmente, contas SSH com privilégios mínimos.

As ferramentas de administração têm o alcance das permissões do usuário configurado: com
`ADMINISTER`, ele cria administradores, muda o destino de qualquer conexão e apaga usuários. Dê
permissões de administração só a quem vai administrar pelo MCP e não libere as ferramentas de
escrita (`create_*`, `update_*`, `delete_*`) sem confirmação.

## Testes

```sh
uv run pytest
```
