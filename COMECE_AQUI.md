# Comece aqui, Gi

O Compose Lens é uma ferramenta local de análise de configurações Docker Compose. Esta primeira versão foi criada com assistência de IA. Ela está funcionando, mas ainda é um protótipo: vale entender e modificar o código antes de apresentá-lo como trabalho seu.

## Rodar no Linux

Abra um terminal dentro da pasta do projeto:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m compose_lens examples/review-needed.yaml --fail-on none
python -m unittest discover -s tests -v
```

Se o Ubuntu informar que `venv` não está disponível, instale o pacote `python3-venv` pelo gerenciador de pacotes do sistema e repita a criação do ambiente. A instalação das dependências precisa de internet; a análise não.

## Entender em uma sessão curta

1. Compare os dois YAML em `examples/`. Eles são fictícios; não execute `docker compose up` com eles.
2. Rode a análise dos dois e confira por que cada regra apareceu ou deixou de aparecer.
3. Leia a classe `Finding` e a função `audit` em `compose_lens/audit.py`.
4. Escolha uma regra, altere uma configuração em uma cópia do exemplo e tente prever a saída antes de rodar.
5. Leia um teste correspondente e faça sua primeira melhoria. Uma boa tarefa: criar um aviso explícito quando `network_mode` contiver `${...}`, porque o programa não resolve essas variáveis.

A ausência de alertas não é uma garantia de segurança. O projeto analisa texto; não conhece a configuração real da máquina.

## Levar ao GitHub

O pacote inclui um repositório Git com um commit inicial identificado como criação assistida por IA. Não inclui uma conexão com uma conta ou repositório remoto.

Crie um repositório vazio chamado `compose-lens` na sua conta, sem README ou licença automáticos, para evitar conflitos com os arquivos existentes. Depois use a URL real desse repositório:

```bash
git remote add origin URL_DO_SEU_REPOSITORIO
git push -u origin main
```

Escolha a visibilidade na criação do repositório; a vaga fornecida não exige que ele seja público. Configure seu nome e e-mail do Git antes de criar seus próprios commits, se ainda não tiver feito isso. Um endereço noreply do GitHub pode ser usado.

## Sobre a candidatura

Descreva-o como um protótipo pessoal em Python para revisão estática de Docker Compose, iniciado com assistência de IA, que você pretende desenvolver e validar. Não o apresente como scanner completo, projeto usado em produção ou como implementação inteiramente manual.

O escopo é defensivo: analisar arquivos locais e explicar configurações. Não faz exploração, treinamento ou avaliação de modelos. A aprovação do projeto cabe à organização da vaga.

O README tem um pequeno roteiro de melhorias para continuar durante as sessões. Nas sessões da vaga, as avaliações das respostas precisam ser escritas por você, sem IA, conforme o anúncio. Use exemplos sintéticos e não coloque credenciais ou dados pessoais de outras pessoas nas sessões.
