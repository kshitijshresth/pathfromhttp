def run_query(term):
    sql = "SELECT * FROM users WHERE name = '" + term + "'"
    return execute(sql)


def execute(sql):
    return sql
