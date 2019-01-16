/* globals twoFactor */

twoFactor.options = {};

const generateCode = () => {
  return Array(...Array(6))
    .map(() => {
      return Math.floor(Math.random() * 10);
    })
    .join('');
};

const NonEmptyString = Match.Where(x => {
  check(x, String);
  return x.length > 0;
});

const userQueryValidator = Match.Where(user => {
  check(user, {
    id: Match.Optional(NonEmptyString),
    username: Match.Optional(NonEmptyString),
    email: Match.Optional(NonEmptyString),
  });
  if (Object.keys(user).length !== 1) {
    throw new Match.Error('User property must have exactly one field');
  }
  return true;
});

const passwordValidator = { digest: String, algorithm: String };

const invalidLogin = ({user, methodInvocation, userQuery, method}) => {
  let error = createError(403, 'Invalid login credentials');
  reportLoginFailure({error, user, methodInvocation, userQuery, method})
  return error;
};

const invalidCode = ({user, methodInvocation, userQuery, method})=>{
  let error = createError(403, 'Invalid code');
  reportLoginFailure({error, user, methodInvocation, userQuery, method})
  return error;
}

const createError = (code, reason)=>{
  return new Meteor.Error(code, reason);
}

const reportLoginFailure = ({error, user, methodInvocation, userQuery, method})=>{
  Accounts._reportLoginFailure(methodInvocation, method, [{user: userQuery}], {error, userId: user && user._id, type: 'login'});
  //console.log(method, [userQuery], {error, userId: user && user._id, type: 'login'});
}

const getFieldName = () => {
  return twoFactor.options.fieldName || 'twoFactorCode';
};

Meteor.methods({
  'twoFactor.getAuthenticationCode'(userQuery, password) {
    check(userQuery, userQueryValidator);
    check(password, passwordValidator);

    const fieldName = getFieldName();

    const user = Accounts._findUserByQuery(userQuery);
    const errorParams = {user, methodInvocation: this, userQuery, method: 'twoFactor.getAuthenticationCode'};
    if (!user) {
      throw invalidLogin(errorParams);
    }

    const checkPassword = Accounts._checkPassword(user, password);
    if (checkPassword.error) {
      throw invalidLogin(errorParams);
    }

    const code =
      typeof twoFactor.generateCode === 'function'
        ? twoFactor.generateCode()
        : generateCode();

    if (typeof twoFactor.sendCode === 'function') {
      twoFactor.sendCode(user, code);
    }

    Meteor.users.update(user._id, {
      $set: {
        [fieldName]: code,
      },
    });
  },
  'twoFactor.verifyCodeAndLogin'(options) {
    check(options, {
      user: userQueryValidator,
      password: passwordValidator,
      code: String,
    });

    const fieldName = getFieldName();

    const user = Accounts._findUserByQuery(options.user);
    const errorParams = {user, methodInvocation: this, userQuery: options.user, method: 'twoFactor.verifyCodeAndLogin'};
    if (!user) {
      throw invalidLogin(errorParams);
    }

    const checkPassword = Accounts._checkPassword(user, options.password);
    if (checkPassword.error) {
      throw invalidLogin(errorParams);
    }

    if (options.code !== user[fieldName]) {
      throw invalidCode(errorParams);
    }

    Meteor.users.update(user._id, {
      $unset: {
        [fieldName]: '',
      },
    });

    return Accounts._attemptLogin(this, 'login', '', {
      type: '2FALogin',
      userId: user._id,
    });
  },
  'twoFactor.abort'(userQuery, password) {
    check(userQuery, userQueryValidator);
    check(password, passwordValidator);

    const fieldName = getFieldName();

    const user = Accounts._findUserByQuery(userQuery);
    const errorParams = {user, methodInvocation: this, userQuery, method: 'twoFactor.abort'};
    if (!user) {
      throw invalidLogin(errorParams);
    }

    const checkPassword = Accounts._checkPassword(user, password);
    if (checkPassword.error) {
      throw invalidLogin(errorParams);
    }

    Meteor.users.update(user._id, {
      $unset: {
        [fieldName]: '',
      },
    });
  },
});

Accounts.validateLoginAttempt(options => {
  const customValidator = () => {
    if (typeof twoFactor.validateLoginAttempt === 'function') {
      return twoFactor.validateLoginAttempt(options);
    }
    return false;
  };

  const allowedMethods = ['createUser', 'resetPassword', 'verifyEmail'];

  if (
    customValidator() ||
    options.type === 'resume' ||
    allowedMethods.indexOf(options.methodName) !== -1
  ) {
    return true;
  }

  if (options.type === '2FALogin' && options.methodName === 'login') {
    return options.allowed;
  }

  return false;
});
