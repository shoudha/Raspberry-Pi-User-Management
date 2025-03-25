Device Management & Security for IoT Platform

Purpose:
  To Encrypt the raw data, read from the sensors using AES-128
  To Decrypt the data and providing the filtered data according to the Role (Role-Bases Access Control)
  Using Key Management we can have different users with different passwords

Specifications
Processor:
  Encrypts the data using the AES-128 algorithm.
  Stores and fetches the data from the storage file/cloud
  Verifies the identity of the user
  Filters the data according to the user’s access
Files: All the files will be in an encrypted form
  Storage File: Stores the encrypted data
  RBAC File: Stores the roles of the users
  Password File: Stores the passwords of the users.

Objective
  To verify the user’s identity
  To verify if the user has access to view/request that data
