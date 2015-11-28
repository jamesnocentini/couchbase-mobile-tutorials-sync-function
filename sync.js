function (doc, oldDoc) {
  // We don’t allow changing the type of any document.
  if (isUpdate()) {
    validateReadOnly("type", doc.type, oldDoc.type);
  }

  if (getType() == "moderator") {
    // Only allow admins to add/remove moderators.
    requireRole("admin");

    if (isDelete()) {
      // No need to validate anything else.
    } else {
      // Validate required fields.
      validateNotEmpty("username", doc.username);

      if (isCreate()) {
        // We use a key pattern to ensure unique moderators within the system, 
        // so we need to ensure that doc._id matches the pattern
        // moderator:{username}.
        if (doc._id != "moderator:" + doc.username) {
          throw({forbidden: "_id must match the pattern moderator:{username}."});
        }
      } else {
        // doc._id is tied to username, validated during create, and must remain this
        // way to ensure unique moderators within the system.
        validateReadOnly("username", doc.username, oldDoc.username);
      }

      // Add user to moderator role.
      role(doc.username, "moderator");
    }
  } else if (getType() == "task-list") {
    if (isDelete()) {
      requireUserOrRole(doc.owner, "moderator");
    } else {
      // Validate required fields.
      validateNotEmpty("name", doc.name);
      validateNotEmpty("owner", doc.owner);
      
      if (isCreate()) {
        // Only allow users to create task-lists for themselves.
        requireUser(doc.owner);

        // Validate that the _id is prefixed by owner.
        validatePrefix("_id", doc._id, "owner", doc.owner + ":");
      } else {
        requireUserOrRole(doc.owner, "moderator");

        // Don’t allow task-list ownership to be changed.
        validateReadOnly("owner", doc.owner, oldDoc.owner);
      }

      // Add doc to task-list's channel.
      channel("task-list:" + doc._id);
      channel("moderators");

      // Grant task-list owner access to the task-list, its tasks, and its users.
      access(doc.owner, "task-list:" + doc._id);
      access(doc.owner, "task-list:" + doc._id + ":users");
    }
  } else if (getType() == "task") {
    requireUserOrAccess(doc.taskList.owner, "task-list:" + doc.taskList.id);

    if (isDelete()) {
      // Validate required fields.
      validateNotEmpty("taskList.id", doc.taskList.id);
      validateNotEmpty("taskList.owner", doc.taskList.owner);
      validateNotEmpty("username", doc.username);
  
      if (isCreate()) {
        // Validate that the taskList.id is prefixed by taskList.owner.  We only need to
        // validate this during create because these fields are read-only after create.
        validatePrefix("taskList.id", doc.taskList.id, "taskList.owner", doc.taskList.owner + ":");
      } else {
        // Don’t allow tasks to be moved to another task-list.
        validateReadOnly("taskList.id", doc.taskList.id, oldDoc.taskList.id);
        validateReadOnly("taskList.owner", doc.taskList.owner, oldDoc.taskList.owner);
      }
  
      // Add doc to task-list and moderators channel.
      channel("task-list:" + doc.taskList.id);
      channel("moderators");
    }
  } else if (getType() == "task-list:user") {
    requireUserOrRole(doc.taskList.owner, "moderator");

    if (isDelete()) {
      // Validate required fields.
      validateNotEmpty("taskList.id", doc.taskList.id);
      validateNotEmpty("taskList.owner", doc.taskList.owner);
      validateNotEmpty("task", doc.task);
  
      if (isCreate()) {
        // We use a key pattern to ensure unique users w/in a list, so we need to
        // ensure that doc._id matches the pattern {taskList.id}:{username}.
        if (doc._id != doc.taskList.id + ":" + doc.username) {
          throw({forbidden: "_id must match the pattern {taskList.id}:{username}."});
        }
  
        // Validate that the taskList.id is prefixed by taskList.owner.
        validatePrefix("taskList.id", doc.taskList.id, "taskList.owner", doc.taskList.owner + ":");
      } else {
        // Don’t allow users to be moved to another task-list.  Also, doc._id is tied to
        // these values, validated during create, and must remain this way to ensure
        // uniqueness within a list.
        validateReadOnly("taskList.id", doc.taskList.id, oldDoc.taskList.id);
        validateReadOnly("taskList.owner", doc.taskList.owner, oldDoc.taskList.owner);
      }
  
      // Add doc to task-list users and moderators channel.
      channel("task-list:" + doc.taskList.id + ":users");
      channel("moderators");
  
      // Grant the user access to the task-list and its tasks.
      access(doc.username, "task-list:" + doc.taskList.id);
    }
  } else {
    // Log this unexpected error.
    log("Invalid document type: " + doc.type);

    throw({forbidden: "Invalid document type: " + doc.type});
  }

  function getType() {
    return (isDelete(doc) ? oldDoc.type : doc.type);
  }

  function isCreate() {
    return (oldDoc == null && doc._deleted != true);
  }

  function isUpdate() {
    return (!isCreate(oldDoc) && !isDelete(doc));
  }

  function isDelete() {
    return (doc._deleted == true);
  }

  function requireUserOrRole(user, role) {
    try {
      requireUser(user);
    } catch (e) {
      requireRole(role);
    }
  }

  function requireUserOrAccess(user, channel) {
    try {
      requireUser(user);
    } catch (e) {
      requireAccess(channel);
    }
  }

  function validateNotEmpty(name, value) {
    if (value == null || value.length == 0 || value.trim().length == 0) {
      throw({forbidden: name + " is empty."});
    }
  }

  function validateReadOnly(name, value, oldValue) {
    if (value != oldValue) {
      throw({forbidden: name + " is read-only."});
    }
  }

  function validatePrefix(name, value, prefixName, prefix) {
    if (value.slice(0, prefix.length) != prefix) {
      throw({forbidden: name + " must be prefixed with " + prefixName + "."});
    }
  }
};
