const db = require('../../data/db-config')
/**
  resolves to an ARRAY with all users, each user having { user_id, username }
 */
async function find() {
  const response = await db('users').select('user_id', 'username')
  return response
}

/**
  resolves to an ARRAY with all users that match the filter condition
 */
async function findBy(param, value) {
  const user = await db('users')
    .from('users')
    .where(`${param}`, value)
    .first()
  return user
}

/**
  resolves to the user { user_id, username } with the given user_id
 */
function findById(user_id) {
  return db.select('user_id', 'username')
    .from('users')
    .where('user_id', user_id)
}

/**
  resolves to the newly inserted user { user_id, username }
 */
async function add(user) {
  await db('users').insert(user)
  const response = await db('users')
    .where('username', user.username)
    .first()
  return response
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  find,
  findBy,
  findById,
  add
}