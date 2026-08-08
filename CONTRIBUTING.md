# Contribuindo para o Ventura.SEG

Obrigado por contribuir.

## Como contribuir

1. Fork o repositório
2. Crie uma branch: `git checkout -b feat/minha-feature`
3. Faça commits com [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` nova funcionalidade
   - `fix:` correção
   - `docs:` documentação
   - `test:` testes
   - `security:` segurança
   - `chore:` manutenção
4. Rode os testes: `PYTHONPATH=src pytest tests/ -v`
5. Abra um Pull Request

## Regras de segurança

- Nunca commit de segredos, tokens ou `.env`
- Report de vulnerabilidades: veja [SECURITY.md](SECURITY.md)
- Mudanças em políticas YAML devem incluir testes

## Ambiente local

```bash
pip install -r requirements.txt
export PYTHONPATH=src
pytest tests/ -v
```
