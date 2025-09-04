export const getUserProfile = [
  authenticateToken, // ✅ Middleware runs first
  async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      return next(err)
    }

    // ✅ Use req.user (set by JWT middleware)
    const loggedInUser = (req as any).user
    if (!loggedInUser || !loggedInUser.id) {
      return res.status(401).json({ error: 'Unauthorized: Invalid or missing user.' })
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.id)
    } catch (error) {
      return next(error)
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    // 👉 If client wants JSON (e.g. Postman, API use), return raw user
    if (req.headers['accept']?.includes('application/json')) {
      return res.json({ user })
    }

    // --- otherwise continue with HTML rendering ---
    let username = user.username

    // ✅ Handle XSS challenge logic
    if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
      req.app.locals.abused_ssti_bug = true
      const code = username?.substring(2, username.length - 1)
      try {
        if (!code) throw new Error('Username is null')
        username = eval(code) // eslint-disable-line no-eval
      } catch (err) {
        username = '\\' + username
      }
    } else {
      username = '\\' + username
    }

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) template = template.replace(/_username_/g, username)
    template = template.replace(/_emailHash_/g, utils.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    const fn = pug.compile(template)
    const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval' https://code.getmdl.io http://ajax.googleapis.com`

    challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
      return username &&
        user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null &&
        utils.contains(username, '<script>alert(`xss`)</script>')
    })

    res.set({ 'Content-Security-Policy': CSP })
    res.send(fn(user))
  }
]
