package gbox

import (
	"fmt"
	"testing"

	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
	"github.com/stretchr/testify/require"
)

func TestCachingTagAnalyzer_AnalyzeResult_WithoutTypeKeys(t *testing.T) {
	cr := newTestCachingRequest()
	tags := make(cachingTags)
	analyzer := newCachingTagAnalyzer(cr, nil)
	err := analyzer.AnalyzeResult([]byte(`{"data": {"users":[{"name":"A"}]}}`), nil, tags)
	sh, _ := cr.schema.Hash()

	require.NoError(t, err)
	require.Equal(t, tags.Types().ToSlice(), []string{"type:Query", "type:User"})
	require.Equal(t, []string{fmt.Sprintf(cachingTagSchemaHashPattern, sh)}, tags.SchemaHash().ToSlice())
	require.Equal(t, tags.TypeFields().ToSlice(), []string{"field:Query:users", "field:User:name"})
	require.Equal(t, tags.TypeKeys().ToSlice(), []string{})

	for _, request := range *cr.gqlRequests {
		require.Equal(t, tags.Operation().ToSlice(), []string{fmt.Sprintf(cachingTagOperationPattern, request.OperationName)})
	}
}

func TestCachingTagAnalyzer_AnalyzeResult_WithTypeKeys(t *testing.T) {
	cr := newTestCachingRequest()
	tags := make(cachingTags)
	analyzer := newCachingTagAnalyzer(cr, graphql.RequestTypes{
		"User": graphql.RequestFields{
			"name": struct{}{},
		},
	})
	err := analyzer.AnalyzeResult([]byte(`{"data": {"users":[{"name":"A"}]}}`), nil, tags)
	sh, _ := cr.schema.Hash()

	require.NoError(t, err)
	require.Equal(t, tags.Types().ToSlice(), []string{"type:Query", "type:User"})
	require.Equal(t, []string{fmt.Sprintf(cachingTagSchemaHashPattern, sh)}, tags.SchemaHash().ToSlice())
	require.Equal(t, tags.TypeFields().ToSlice(), []string{"field:Query:users", "field:User:name"})
	require.Equal(t, tags.TypeKeys().ToSlice(), []string{"key:User:name:A"})
	for _, request := range *cr.gqlRequests {
		require.Equal(t, tags.Operation().ToSlice(), []string{fmt.Sprintf(cachingTagOperationPattern, request.OperationName)})
	}
}

func TestCachingTagAnalyzer_AnalyzeResult_OnlyTypes(t *testing.T) {
	cr := newTestCachingRequest()
	tags := make(cachingTags)
	analyzer := newCachingTagAnalyzer(cr, graphql.RequestTypes{
		"User": graphql.RequestFields{
			"name": struct{}{},
		},
	})
	err := analyzer.AnalyzeResult(
		[]byte(`{"data": {"users":[{"name":"A"}]}}`),
		map[string]struct{}{"Unknown": {}},
		tags,
	)
	sh, _ := cr.schema.Hash()

	require.NoError(t, err)
	require.Equal(t, tags.Types().ToSlice(), []string{"type:Query"})
	require.Equal(t, []string{fmt.Sprintf(cachingTagSchemaHashPattern, sh)}, tags.SchemaHash().ToSlice())
	require.Equal(t, tags.TypeFields().ToSlice(), []string{"field:Query:users"})
	require.Equal(t, tags.TypeKeys().ToSlice(), []string{})
	for _, request := range *cr.gqlRequests {
		require.Equal(t, tags.Operation().ToSlice(), []string{fmt.Sprintf(cachingTagOperationPattern, request.OperationName)})
	}
}
