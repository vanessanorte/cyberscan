# 🔐 CyberScan Smart — Scanner Inteligente de Portas

O **CyberScan Smart** é um scanner de portas desenvolvido em Python com foco em análise de segurança de rede, identificação de serviços expostos e interpretação contextual de riscos.

Diferente de ferramentas básicas, este projeto não apenas detecta portas abertas, mas também analisa o ambiente para fornecer uma visão mais realista do nível de risco.

---

## 💡 Diferencial

- Não apenas identifica portas abertas  
- Interpreta o contexto (interno vs externo)  
- Ajusta automaticamente a classificação de risco  
- Reduz falsos positivos (ex: portas efêmeras)  

💥 Segurança não é só detectar — é entender.

---

## ⚙️ Funcionalidades

- Scan de portas (rápido e completo até 65535)
- Multithreading (alta performance)
- Resolução de domínio para IP
- Classificação inteligente de risco (baixo, médio, alto)
- Score de segurança do sistema
- Identificação de serviços por porta
- Detecção de ambiente (interno / externo)
- Análise automática dos resultados
- Recomendações de segurança
- Geração de relatórios em TXT e JSON

---

## 📊 Exemplo de uso

Durante testes em ambiente interno:

- 65.535 portas analisadas  
- 13 portas abertas identificadas  
- Score de segurança: **70/100**  

A porta **445 (SMB)** foi identificada como sensível, porém:

- Serviço comum em ambiente Windows  
- Acesso restrito à rede interna  
- Sem exposição externa detectada  

👉 Classificação ajustada com base no contexto

---

## 🧠 Lógica de análise

O scanner aplica heurísticas como:

- Identificação de portas efêmeras (alta numeração)
- Avaliação de exposição externa
- Ajuste de risco baseado no ambiente
- Correlação entre serviço e criticidade

---

## 📁 Estrutura do projeto

cyberscan/  
├── scanner.py  
├── README.md  
├── reports/  
│   ├── report_xxx.txt  
│   └── report_xxx.json  

---

## ▶️ Como executar

Clone o repositório:

```bash
git clone https://github.com/seu-usuario/cyberscan.git
cd cyberscan

## ▶️ Execute o Scanner 
python scanner.py

Siga as instruções no terminal informando o alvo eo tipo de scan.

⚠️ Aviso legal

Este projeto é destinado exclusivamente para fins educacionais.

Não utilize em sistemas sem autorização.

🚀 Próximas melhorias
Banner grabbing avançado (detecção de versão de serviços)
Integração com base de vulnerabilidades (CVE)
Interface gráfica (GUI)
Detecção automática de exposição externa
Dashboard interativo

👩‍💻 Autora
Vanessa Teles Norte

Projeto desenvolvido como parte da evolução prática em Cibersegurança.