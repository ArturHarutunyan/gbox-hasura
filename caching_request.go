package gbox

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astnormalization"
	"github.com/jensneuse/graphql-go-tools/pkg/astparser"
	"github.com/jensneuse/graphql-go-tools/pkg/graphql"
	"github.com/pquerna/cachecontrol/cacheobject"
)

type cachingRequest struct {
	httpRequest           *http.Request
	schema                *graphql.Schema
	gqlRequests           *[]graphql.Request
	definition, operation *ast.Document
	cacheControl          *cacheobject.RequestCacheDirectives
	UserInfo              map[string]string
}

func newCachingRequest(r *http.Request, d *ast.Document, s *graphql.Schema, gr *[]graphql.Request, JWTKey string) *cachingRequest {
	userInfo := make(map[string]string)
	tokenString := r.Header.Get("Authorization")
	if len(tokenString) > 8 {
		tokenString = tokenString[7:]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Check the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Return the secret key used to sign the token
			return []byte(JWTKey), nil
		})
		// Check if there was an error parsing the token
		if err == nil {
			// Get the claims from the token
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				fmt.Println("Error getting claims")
				return nil
			}
			hasuraData := claims["https://hasura.io/jwt/claims"].(map[string]interface{})
			roles, ok := hasuraData["x-hasura-allowed-roles"].([]interface{})
			if !ok {
				fmt.Println("Error getting roles")
				return nil
			}

			var rolesStr []string
			for _, role := range roles {
				rolesStr = append(rolesStr, role.(string))
			}

			rolesString := strings.Join(rolesStr[:], ",")

			userInfo["role"] = rolesString
			defaultRole, ok := hasuraData["x-hasura-default-role"]
			if !ok {
				fmt.Println("Error getting default roles")
				return nil
			}

			userInfo["defaultRole"] = defaultRole.(string)

			unmarshalCaddyFileCaching, ok := claims["sub"]
			if !ok {
				fmt.Println("Error getting id")
				return nil
			}
			userInfo["unmarshalCaddyFileCaching"] = unmarshalCaddyFileCaching.(string)

		}
	}
	cr := &cachingRequest{
		httpRequest: r,
		schema:      s,
		definition:  d,
		gqlRequests: gr,
		UserInfo:    userInfo,
	}
	cacheControlString := r.Header.Get("cache-control")
	cr.cacheControl, _ = cacheobject.ParseRequestCacheControl(cacheControlString)

	return cr
}

func (r *cachingRequest) initOperation() error {
	if r.operation != nil {
		return nil
	}

	for _, request := range *r.gqlRequests {
		operation, report := astparser.ParseGraphqlDocumentString(request.Query)

		if report.HasErrors() {
			return &report
		}

		operation.Input.Variables = request.Variables
		normalizer := astnormalization.NewWithOpts(
			astnormalization.WithExtractVariables(),
			astnormalization.WithRemoveFragmentDefinitions(),
			astnormalization.WithRemoveUnusedVariables(),
		)

		if request.OperationName != "" {
			normalizer.NormalizeNamedOperation(&operation, r.definition, []byte(request.OperationName), &report)
		} else {
			normalizer.NormalizeOperation(&operation, r.definition, &report)
		}

		if report.HasErrors() {
			return &report
		}

		r.operation = &operation
	}

	return nil
}
