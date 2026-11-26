# VT Hash Scanner

Ferramenta de linha de comando em Python que consulta a reputação de arquivos (fotos, músicas, PDFs, documentos, executáveis...) no [VirusTotal](https://www.virustotal.com) a partir do hash SHA-256.

**O arquivo nunca é enviado nem aberto.** A ferramenta só lê os bytes localmente para calcular o hash, e somente o hash é consultado.

## O que faz

- Verifica um ou vários arquivos, ou pastas inteiras (`-r` para subpastas)
- Mostra quantos mecanismos de antivírus marcaram o arquivo como malicioso ou suspeito, com link para o relatório completo
- Respeita o limite de consultas da API (intervalo configurável, tratamento de erro 429)
- Exporta o relatório em JSON ou CSV (sem sobrescrever arquivos existentes)
- Código de saída útil para scripts: `0` sem alertas, `1` com alerta, `2` erro

## Como instalar

```bash
git clone https://github.com/BrunoCoelho-dev/vt-hash-scanner.git
cd vt-hash-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
```

Crie uma conta gratuita no VirusTotal, copie sua chave de API e cole em `.env`:

```
VT_API_KEY=sua_chave_aqui
```

## Como usar

```bash
python scanner.py arquivo.pdf
python scanner.py foto.jpg musica.mp3
python scanner.py ~/Downloads -r --json relatorio.json
```

Opções: `--max-files N`, `--interval SEGUNDOS`, `--json ARQUIVO`, `--csv ARQUIVO`.

## Como ler o resultado

| Resultado | Significado |
|---|---|
| MALICIOSO / SUSPEITO | Um ou mais mecanismos detectaram algo. Não abra o arquivo. |
| SEM DETECÇÕES | Nenhum mecanismo detectou, **mas isso não garante que seja seguro**. |
| DESCONHECIDO | O VirusTotal nunca viu o arquivo, **o que também não garante que seja seguro**. |

## Decisões de segurança

- Só o hash SHA-256 sai do computador; o conteúdo do arquivo nunca é enviado.
- Arquivos não são interpretados (nada de abrir PDF, imagem ou áudio com bibliotecas), o que evita explorar falhas de parsers.
- A chave da API fica em `.env` (fora do Git), nunca é impressa, não vai para relatórios e não aparece em mensagens de erro.
- Links simbólicos e arquivos especiais são ignorados, para não sair da pasta escolhida nem travar em pipes.
- Nomes de arquivo são limpos antes de ir ao terminal (evita sequências de escape) e ao CSV (evita injeção de fórmulas em planilhas).
- Consultas só aceitam hash válido gerado localmente, com timeout, sem seguir redirecionamentos e com número limitado de tentativas.

## Testes

```bash
python -m unittest -v
```

Os testes usam respostas simuladas e não gastam consultas da API. O código também foi verificado com `bandit` (análise estática) e `pip-audit` (dependências).

## Limitações

- A ferramenta não detecta malware: quem detecta são os mecanismos do VirusTotal. Ela apenas consulta o que eles já sabem.
- Arquivos novos ou modificados (hash inédito) aparecem como desconhecidos.
- A conta gratuita do VirusTotal tem limite de consultas e é só para uso pessoal e não comercial; confira os termos atuais.

## Próximos passos

- [ ] Cache local de resultados para economizar consultas
- [ ] Opção de enviar o arquivo ao VirusTotal, com confirmação explícita do usuário
- [ ] Interface web local (somente na máquina do usuário)

## Aviso

Projeto de estudo. Não substitui um antivírus.