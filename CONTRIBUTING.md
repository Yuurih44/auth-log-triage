# Contribuir

Abra uma issue com o comportamento observado, a versão do Python e os passos mínimos para reprodução. Use exemplos sintéticos; não inclua credenciais, cookies ou logs com dados pessoais.

## Ambiente local

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# No Windows, use .venv\Scripts\Activate.ps1 no PowerShell.
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
python -m unittest -v
```

Para formatar alterações, use `ruff format .`. Para mudanças de comportamento, inclua um teste que demonstre o problema e atualize os exemplos afetados. Alterações devem manter compatibilidade com Python 3.10 ou superior.

O escopo é educacional e local. Preserve a descrição das limitações e a atribuição de contribuições. Não publique alegações de segurança ou resultados de testes que não tenham sido verificados.
