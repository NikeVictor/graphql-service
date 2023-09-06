const express = require('express');
const { ApolloServer, gql } = require('apollo-server-express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require("dotenv").config()

const app = express();
const port = process.env.PORT || 4000;

const typeDefs = gql`
  type User {
    id: ID!
    username: String!
  }

  type Query {
    me: User
  }

  type Mutation {
    signup(username: String!, password: String!): String
    login(username: String!, password: String!): String
  }
`;

const users = [];
const SECRET_KEY = process.env.SECRET_KEY;
const resolvers = {
  Query: {
    me: (context) => {
      return context.user;
    },
  },
  Mutation: {
    signup: async ({ username, password }) => {
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = { id: users.length + 1, username, password: hashedPassword };
      users.push(user);

      return jwt.sign({ userId: user.id }, SECRET_KEY);
    },
    login: async ({ username, password }) => {
      const user = users.find((u) => u.username === username);

      if (user && (await bcrypt.compare(password, user.password))) {
        return jwt.sign({ userId: user.id }, SECRET_KEY);
      }

      throw new Error('Invalid login credentials');
    },
  },
};


const startServer = async () => {
    const server = new ApolloServer({
      typeDefs,
      resolvers,
      context: ({ req }) => {
        const token = req.headers.authorization || '';
        try {
          const user = jwt.verify(token, SECRET_KEY);
          return { user };
        } catch (error) {
          return {};
        }
      },
    });
  
    await server.start();
  
    server.applyMiddleware({ app });
  
    app.listen(port, () => {
      console.log(`GraphQL server is running`);
    });
  };
  
  startServer();
