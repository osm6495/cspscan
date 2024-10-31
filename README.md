<a name="readme-top"></a>

<!-- PROJECT SHIELDS -->

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url] [![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/osm6495/cspscan/">
  </a>

<h3 align="center">CSPScan</h3>

<p align="center">
   A CLI toolkit to find dangling cloud storage bucket in Content Security Policy directives.
    <br />
    <a href="https://github.com/osm6495/cspscan/">View Demo</a>
    ·
    <a href="https://github.com/osm6495/cspscan/issues">Report Bug</a>
    ·
    <a href="https://github.com/osm6495/cspscan/issues">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#usage">Usage</a>
      <ul>
        <li><a href="#examples">Examples</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#installing-the-latest-version">Installing the latest version</a></li>
        <li><a href="#installing-from-source">Installing from source</a></li>
      </ul>
    </li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

<!-- ABOUT -->

## Usage

```
A CLI toolkit to find dangling cloud storage buckets in Content Security Policy directives.

Usage:
  cspscan [options] <-u targetUrl | targetUrlList> [flags]

Flags:
  -h, --help          help for cspscan
  -t, --threads int   limit the number of threads, which will 
                      make one HEAD request to each input url, and one GET request to each url in the CSP for each input URL.
                      A value of 0 will not limit the thread count.
  -u, --url string    specify a single URL, rather than a filepath to a list of URLs
  -v, --verbose       output all scanned URLs, even if not vulnerable
```

Example:

```
$ cspscan -u https://github.com -v
Scanned URL: https://github.com/webpack/
Scanned URL: https://github.com/assets-cdn/worker/
...
```

<!-- GETTING STARTED -->

## Getting Started

### Installing the latest version

You can use download a pre-built binary directly from the latest release:
https://github.com/osm6495/cspscan/releases

1. Select the latest version at the top of the page and open the `Assets`
   section
2. Download the file that applies for your system
3. (Optional) Move the binary to your `/usr/bin` directory for Linux and Mac or
   `C:\Program Files` for Windows. This will allow you to use the `cspscan`
   command without directly calling the binary or having the source code.

### Installing from Source

_Below is an example of how you can instruct your audience on installing and
setting up your app. This template doesn't rely on any external dependencies or
services._

1. Install Rust: [http://rust-lang.org/](http://rust-lang.org/)
2. Clone the repo

```sh
git clone https://github.com/osm6495/cspscan
cd cspscan
```

3. Build the binary

```sh
cargo build --release
```

4. Run the program

```sh
./target/release/cspscan -h
```

5. (Optional) Move the binary to your `/usr/bin` directory for Linux and Mac or
   `C:\Program Files` for Windows. This will allow you to use the `cspscan`
   command without directly calling the binary or having the source code.

```sh
sudo mv ./target/release/cspscan /usr/bin/cspscan
```

<!-- ROADMAP -->

## Roadmap

- [ ] Add spinner to show user that scan is working when not using the `-v` flag
- [ ] Allow for a `--depth` flag that would allow you to check CSP urls
      recursively for further CSPs
- [ ] Allow for output customization options

See the [open issues](https://github.com/osm6495/cspscan/issues) for a full list
of proposed features (and known issues).

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to
learn, inspire, and create. Any contributions you make are **greatly
appreciated**.

If you have a suggestion that would make this better, please fork the repo and
create a pull request. You can also simply open an issue with the tag
"enhancement". Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<!-- CONTACT -->

## Contact

Owen McCarthy - contact@owen.biz

<!-- ACKNOWLEDGEMENT -->

## Acknowledgements

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/osm6495/cspscan.svg?color=orange
[contributors-url]: https://github.com/osm6495/cspscan/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/osm6495/cspscan.svg?style=flat&color=orange
[forks-url]: https://github.com/osm6495/cspscan/network/members
[stars-shield]: https://img.shields.io/github/stars/osm6495/cspscan.svg?style=flat&color=orange
[stars-url]: https://github.com/osm6495/cspscan/stargazers
[issues-shield]: https://img.shields.io/github/issues/osm6495/cspscan.svg?color=orange
[issues-url]: https://github.com/osm6495/cspscan/issues
[license-shield]: https://img.shields.io/github/license/osm6495/cspscan.svg?color=orange
[license-url]: https://github.com/osm6495/cspscan/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?color=blue&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/owen-mccarthy-060827192/
