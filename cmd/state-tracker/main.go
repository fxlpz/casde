// CASDE - Continuous Attack Surface & Diff Engine
//
// CLI unificada com os 6 módulos:
//
//	state     Módulo 1: State Tracker (snapshot/diff/commits)
//	jsast     Módulo 2: JS AST Extractor (endpoints/rotas/secrets)
//	params    Módulo 3: Parameter Scoring Engine
//	fuzz      Módulo 4: Feedback-Guided Fuzzer
//	oob       Módulo 5: OOB Correlator (listener local)
//	findings  Módulo 6: Findings Database (consulta/gestão)
//
// AVISO LEGAL / USO RESPONSÁVEL:
// Esta ferramenta é destinada EXCLUSIVAMENTE a:
//   - Programas de Bug Bounty com escopo autorizado (HackerOne, Bugcrowd, etc.)
//   - Engajamentos de pentest com contrato/escopo definido por escrito
//   - Ambientes próprios ou de laboratório (CTF, homelab)
//
// O monitoramento contínuo de superfície de ataque sem autorização pode
// violar leis locais e os termos de serviço do alvo. O autor não se
// responsabiliza pelo uso indevido.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
)

const banner = `
  ╔══════════════════════════════════════════════════╗
  ║  CASDE - Continuous Attack Surface & Diff Engine ║
  ║  Use somente em alvos autorizados                ║
  ╚══════════════════════════════════════════════════╝`

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	fmt.Println(strings.TrimSuffix(banner, "\n"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	switch os.Args[1] {
	case "state", "tracker":
		cmdRun(ctx, os.Args[2:])
	case "targets":
		cmdTargets(ctx, os.Args[2:])
	case "history":
		cmdHistory(ctx, os.Args[2:])
	case "jsast":
		cmdJSAST(ctx, os.Args[2:])
	case "params":
		cmdParams(ctx, os.Args[2:])
	case "fuzz":
		cmdFuzz(ctx, os.Args[2:])
	case "oob":
		cmdOOB(ctx, os.Args[2:])
	case "findings":
		cmdFindings(ctx, os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "comando desconhecido: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`CASDE - Continuous Attack Surface & Diff Engine

Uso: casde <comando> [flags]

Módulos:
  state     Módulo 1: State Tracker (snapshot + diff + commits)
              casde state --target target.com --urls urls.txt [--db casde.db] [--concurrency 10]
              casde targets [--db casde.db]
              casde history --target target.com [--db casde.db]
  jsast     Módulo 2: JS AST Extractor (requer node + esprima)
              casde jsast --url https://target.com/app.js [--out dir] [--db casde.db]
              casde jsast --file bundle.js
  params    Módulo 3: Parameter Scoring Engine (requer python3)
              casde params --params id,url,file,debug [--sources js,wayback] | casde params --file params.json
  fuzz      Módulo 4: Feedback-Guided Fuzzer
              casde fuzz --target "https://target.com/api?file={{{FUZZ}}}" [--method GET]
              casde fuzz --target "https://target.com/login" --method POST --data "user=admin&pass={{{FUZZ}}}"
              [--param nome] [--generations 4] [--population 24] [--concurrency 8] [--db casde.db]
  oob       Módulo 5: OOB Correlator (listener local)
              casde oob listen --addr :8080 --domain probe.local
  findings  Módulo 6: Findings Database
              casde findings list [--target nome] [--status open] [--db casde.db]
              casde findings set --id 1 --status confirmed --severity high [--db casde.db]

Exemplos:
  casde state --target target.com --urls urls.txt
  casde jsast --url https://target.com/app.js
  casde fuzz --target "https://target.com/search?q={{{FUZZ}}}"
  casde findings list --target target.com --status open
`)
}
