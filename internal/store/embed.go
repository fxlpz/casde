package store

import _ "embed"

// schemaSQL é o schema completo embutido no binário via go:embed.
// O arquivo schema.sql na raiz do repo é a fonte de verdade (mantido em
// sincronia manual); embutir garante que o binário funciona de qualquer cwd.
//
//go:embed schema.sql
var schemaSQL string
