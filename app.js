// Importaciones necesarias para la aplicación

// Framework de Node.js para crear aplicaciones web y API de forma rápida y fácil
import express from 'express'; 

/* Middleware de Express para analizar el cuerpo de las solicitudes 
entrantes en un middleware antes de los manejadores, disponible bajo la propiedad req.body*/
import bodyParser from 'body-parser'; 

// Módulo de criptografía para realizar operaciones como hashing y generación de UUIDs y bytes aleatorios
import { scrypt, randomBytes, randomUUID } from 'crypto'; 

// Creación de una instancia de una aplicación Express
const app = express();

// Configuración de middleware global
app.use(bodyParser.json()); // Para analizar bodies de tipo application/json
app.use(express.static('public')); // Para servir archivos estáticos desde el directorio 'public'

// Almacenamiento simulado: usuarios y tareas (to-dos)
const users = [{
    // Ejemplo de un usuario almacenado con contraseña hasheada
    username: 'admin',
    name: 'Gustavo Alfredo Marín Sáez',
    password: '1b6ce880ac388eb7fcb6bcaf95e20083:341dfbbe86013c940c8e898b437aa82fe575876f2946a2ad744a0c51501c7dfe6d7e5a31c58d2adc7a7dc4b87927594275ca235276accc9f628697a4c00b4e01'
}];
const todos = []; // Lista para almacenar las tareas

	// Función asincrónica para validar la contraseña ingresada contra el hash almacenado
	async function validarContraseña(contraseña, hashAlmacenado) {
    // Descomposición del hash almacenado en sal y hash
    const [salt, hash] = hashAlmacenado.split(':');
    // Generación del hash de la contraseña ingresada para su verificación
    const hashRecreado = await generarHash(contraseña, salt);
    // Comprobación de igualdad entre el hash recreado y el almacenado
    return hashRecreado === hash;
}

// Función asincrónica para generar un hash de una contraseña, utilizando un salt
async function generarHash(contraseña, salt) {
    return new Promise((resolve, reject) => {
        // Uso de scrypt para generar un hash seguro de la contraseña
        scrypt(contraseña, salt, 64, (err, derivedKey) => {
            if (err) reject(err); // En caso de error, la promesa se rechaza
            resolve(derivedKey.toString('hex')); // Si no hay errores, se resuelve la promesa con el hash en formato hexadecimal
        });
    });
}

// Función para generar un token de acceso (no se utiliza en el código para la autenticación real)
function generarBearerToken(username) {
    // Creación de los datos del token, incluyendo el nombre de usuario
    const tokenData = {
        username: username,
    };
    // Conversión de los datos del token a una cadena JSON
    return JSON.stringify(tokenData);
}

// Middleware para validar la autenticación del usuario a partir de un header personalizado
function validateMiddleware(req, res, next) {
    // Extracción del header de autorización
    const authHeader = req.headers['x-authorization'];
    // Verificación de que el header no esté vacío
    if (authHeader && authHeader.trim() !== '') {
        try {
            // Parseo del header de autorización a un objeto JSON
            const userToken = JSON.parse(authHeader);
            // Comprobación de que el usuario exista en la base de datos simulada
            if (users.some(u => u.username === userToken.username)) {
                next(); // Continuar con el siguiente middleware/ruta si el usuario es válido
                return;
            }
        } catch (error) {
            console.error('Error al analizar el encabezado de autorización JSON:', error.message);
        }
    }
    // Enviar una respuesta de estado 401 si la autenticación falla
    res.status(401).send('Acceso denegado o token inválido.');
}

// Definición de rutas para la API
// Ruta de prueba para verificar que el servidor está funcionando
app.get('/api', (req, res) => {
    res.status(200).send('Hello World!');
});

// Ruta para el inicio de sesión de usuarios
app.post('/api/login', async (req, res) => {
    // Extracción del nombre de usuario y contraseña de la solicitud
    const { username, password } = req.body;
    // Validación básica de la entrada
    if (!username || !password) {
        res.status(400).send("Ingrese un usuario y contraseña válidos");
        return;
    }
    // Búsqueda del usuario en la "base de datos"
    const user = users.find(u => u.username === username);
    // Validación de la contraseña y respuesta adecuada
    if (!user || !(await validarContraseña(password, user.password))) {
        res.status(401).send("Usuario o contraseña Incorrectos");
        return;
    }
    // Generación y envío del token (aunque en este código el token no se utiliza realmente para la autenticación)
    const token = generarBearerToken(username);
    res.status(200).json({ username: user.username, name: user.name, token });
});

// Rutas CRUD para la gestión de "to-dos"
// Listar todos los "to-dos"
app.get("/api/todos", validateMiddleware, (req, res) => {
    res.status(200).json(todos);
});

// Obtener un "to-do" específico por ID
app.get("/api/todos/:id", validateMiddleware, (req, res) => {
    // Búsqueda del "to-do" por ID
    const todo = todos.find(t => t.id === req.params.id);
    if (!todo) {
        res.status(404).send("Item no existe");
        return;
    }
    res.status(200).json(todo);
});

// Crear un nuevo "to-do"
app.post("/api/todos", validateMiddleware, (req, res) => {
    // Extracción del título del cuerpo de la solicitud
    const { title } = req.body;
    if (!title) {
        res.status(400).send("El título es requerido");
        return;
    }
    // Creación y almacenamiento del nuevo "to-do"
    const todo = { id: randomUUID(), title, completed: false };
    todos.push(todo);
    res.status(201).json(todo);
});

// Actualizar un "to-do" existente
app.put("/api/todos/:id", validateMiddleware, (req, res) => {
    // Extracción de los datos a actualizar
    const { title, completed } = req.body;
    // Búsqueda del índice del "to-do" en el array
    const todoIndex = todos.findIndex(t => t.id === req.params.id);
    if (todoIndex === -1) {
        res.status(404).send("Item no existe");
        return;
    }
    // Actualización del "to-do"
    let updatedTodo = []
    if(title != "" || title != undefined){
         updatedTodo = { ...todos[todoIndex], title };
    }    
    if(completed != "" || completed != undefined){
         updatedTodo = { ...todos[todoIndex], completed };
    }
       
    //const updatedTodo = { ...todos[todoIndex], title, completed };
    todos[todoIndex] = updatedTodo;
    res.status(200).json(updatedTodo);
});

// Eliminar un "to-do"
app.delete("/api/todos/:id", validateMiddleware, (req, res) => {
    // Búsqueda del índice del "to-do" en el array
    const todoIndex = todos.findIndex(t => t.id === req.params.id);
    if (todoIndex === -1) {
        res.status(404).send("Item no existe");
        return;
    }
    // Eliminación del "to-do" del array
    todos.splice(todoIndex, 1);
    // Respuesta sin contenido para indicar éxito
    res.status(204).send();
});

// Exportación de la aplicación para su uso en otro lugar
export default app;
