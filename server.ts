import express from 'express';
import configDotenv from './src/config/dotenv';
import cors from 'cors';
import configAuth from './src/config/authConfig';
import routes from "./src/routers/routes";
import passport from 'passport';

configDotenv();
configAuth();

const app = express();
const port = process.env.PORT;

app.use(passport.initialize());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(routes);

app.get('/', (req, res) => {
  res.send('Hello World!')
});

app.listen(port, () => {
  console.log(`${process.env.APP_NAME} app listening at http://localhost:${port}`);
});
