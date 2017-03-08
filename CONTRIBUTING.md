# Contributing to katello-client-bootstrap

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

The following is a set of guidelines for contributing to **katello-client-bootstrap** and which is hosted on GitHub in the [Katello](https://github.com/Katello) Organization.
These are just guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for katello-client-bootstrap. Following these guidelines helps maintainers and the community understand your report :pencil:, reproduce the behavior :computer: :computer:, and find related reports :mag_right:.


#### How Do I Submit A (Good) Bug Report?

Bugs are tracked as [GitHub issues](https://github.com/Katello/katello-client-bootstrap/issues).

Explain the problem and include additional details to help maintainers reproduce the problem:

* **Use a clear and descriptive title** for the issue to identify the problem.
* **Describe the exact steps which reproduce the problem** in as many details as possible. For example, start by explaining how you started , e.g. which command exactly you used in the terminal, or how you started `bootstrap.py` otherwise. When listing steps, **don't just say what you did, but explain how you did it**.

* **Provide specific examples to demonstrate the steps**. Include links to files or GitHub projects, or copy/pasteable snippets, which you use in those examples. If you're providing snippets in the issue, use [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines). Note: some of the output of `bootstrap.py` contains hostnames and/or other internal information. Feel free to sanitize this data as long as the sanitized data still reproduces your problem.
* **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
* **Explain which behavior you expected to see instead and why.**
* **Include debugging data**
  - run `bootstrap.py` with the `--verbose` option
  - provide relevant Foreman logs (from production.log usually)
  - If bootstrap fails when calling an external command (such as `subscription-manager`, `puppet` or `rhn-migrate-classic-to-rhsm`), try running that command by itself with debugging/verbose options to get more logs.

Provide more context by answering these questions:

* **Can you reproduce the problem?**
* **Did the problem start happening recently** (e.g. after updating to a new version of `bootstrap.py`) or was this always a problem?
* If the problem started happening recently, **can you reproduce the problem in an older version**. i.e.: What's the most recent version in which the problem doesn't happen?
* **Can you reliably reproduce the issue?** If not, provide details about how often the problem happens and under which conditions it normally happens.

Include details about your configuration and environment:

### Suggesting Enhancements

Features are also tracked today as [GitHub issues](https://github.com/Katello/katello-client-bootstrap/issues).

This section guides you through submitting an enhancement suggestion for **katello-client-bootstrap**, including completely new features and minor improvements to existing functionality. Following these guidelines helps maintainers and the community understand your suggestion :pencil: and find related suggestions :mag_right:.


### Your First Contribution

Unsure where to begin contributing to **katello-client-bootstrap** ?

### Developer and contributor notes:

Use `pydoc ./bootstrap.py` to get the code documentation.

Use `awk -F'# >' 'NF>1 {print $2}' ./bootstrap.py` to see the flow of the script.

Generally, we follow a 'fork and branch' workflow:

 - Fork the repository.
 - Clone the forked repository to your local system.
 - Add a Git remote for the original repository.
 - Create a feature branch in which to place your changes.
 - Make your changes to the new branch.
 - Commit the changes to the branch.
 - Push the branch to GitHub.
 - Open a pull request from the new branch to the original repo.
 - Clean up after your pull request is merged.

### Other Notes

 - when testing `bootstrap.py` you will register (and unregister) a lot of systems. It might be advantageous to set the `unregister_delete_host` setting (Under Administer -> Settings -> Katello). This deletes the host when unregistering via `subscription-manager`

### Styleguides

 - Generally follow [PEP8](https://www.python.org/dev/peps/pep-0008/) with the exception of E501 - line too long errors.

### Git Commits and Commit Messages

* When adding a new feature, squash your commits. so that the feature (in its entirety) can be more easily cherry-picked.
* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally
