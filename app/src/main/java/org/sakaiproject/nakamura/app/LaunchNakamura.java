/**
 * Licensed to the Sakai Foundation (SF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The SF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.sakaiproject.nakamura.app;

import java.awt.Color;
import java.awt.Desktop;
import java.awt.Dimension;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.System;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;

import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

/**
 * This is a simple Swing GUI to launch Nakamura (primarily for the benefit of Windows
 * users) from a Java Web Start link.
 * <p>
 * I actually developed this in Netbeans, due to it's support of Swing (and Eclipse's lack
 * of) and copied the code into the app package.
 * 
 * @author Chris Dunstall (cdunstall@csu.edu.au)
 * @version 1.0 January 6 2011.
 */
public class LaunchNakamura extends javax.swing.JFrame {

  private static final long serialVersionUID = 8161160666368638463L;
  public static final int APP_RUNNING = 1;
  public static final int APP_NOT_RUNNING = 0;
  private static String[] savedArgs;
  private int runStatus = APP_NOT_RUNNING; // 0 for off, 1 for on.
  private static final String localhostURL = "http://localhost:8080/";

  /** Creates new form LaunchNakamura */
  public LaunchNakamura() {
    initComponents();

    ImageIcon icon = createImageIcon("/sakaioae-icon.png", "SakaiOAE Logo");
    headingLabel.setIcon(icon);

    String disclaimer = "";
    try {
      disclaimer = getLabelText("/readme.txt");
    } catch (IOException e) {
      disclaimer = "Use at own risk.";
    }

    disclaimerLabel.setText(disclaimer);
    disclaimerLabel.setPreferredSize(new Dimension(1, 1));

    browserButton.setEnabled(false);
  }

  /**
   * This method is called from within the constructor to initialize the form.
   * <p>
   * Note: This code was generated by Netbeans.
   */
  private void initComponents() {

    launchButton = new javax.swing.JButton();
    statusLabel = new javax.swing.JLabel();
    exitButton = new javax.swing.JButton();
    headingLabel = new javax.swing.JLabel();
    disclaimerLabel = new javax.swing.JLabel();
    browserButton = new javax.swing.JButton();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
    setTitle("Launch Nakamura");
    setName("mainFrame"); // NOI18N
    setResizable(false);

    launchButton.setFont(new java.awt.Font("Arial", 0, 13)); // NOI18N
    launchButton.setText("Launch");
    launchButton.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        launchButtonActionPerformed(evt);
      }
    });

    statusLabel.setFont(new java.awt.Font("Arial", 0, 12)); // NOI18N
    statusLabel.setText("Nakamura is not running.");

    exitButton.setFont(new java.awt.Font("Arial", 0, 13)); // NOI18N
    exitButton.setText("Exit");
    exitButton.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        exitButtonActionPerformed(evt);
      }
    });

    headingLabel.setText("SakaiOAE icon");
    headingLabel.setBorder(javax.swing.BorderFactory.createEtchedBorder());

    disclaimerLabel.setFont(new java.awt.Font("Arial", 0, 13)); // NOI18N
    disclaimerLabel.setText("jLabel1");
    disclaimerLabel.setVerticalAlignment(javax.swing.SwingConstants.TOP);
    disclaimerLabel.setAutoscrolls(true);
    disclaimerLabel.setBorder(javax.swing.BorderFactory.createTitledBorder("Disclaimer"));

    browserButton.setText("Open Sakai OAE");
    browserButton.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        browserButtonActionPerformed(evt);
      }
    });

    javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
    getContentPane().setLayout(layout);
    layout.setHorizontalGroup(layout.createParallelGroup(
        javax.swing.GroupLayout.Alignment.LEADING).addGroup(
        layout
            .createSequentialGroup()
            .addGroup(
                layout
                    .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(
                        layout
                            .createSequentialGroup()
                            .addGap(27, 27, 27)
                            .addComponent(launchButton)
                            .addGap(18, 18, 18)
                            .addComponent(statusLabel)
                            .addPreferredGap(
                                javax.swing.LayoutStyle.ComponentPlacement.RELATED, 162,
                                Short.MAX_VALUE)
                            .addComponent(browserButton)
                            .addPreferredGap(
                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(exitButton))
                    .addGroup(
                        javax.swing.GroupLayout.Alignment.CENTER,
                        layout
                            .createSequentialGroup()
                            .addContainerGap()
                            .addComponent(headingLabel,
                                javax.swing.GroupLayout.PREFERRED_SIZE, 149,
                                javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGap(18, 18, 18)
                            .addComponent(disclaimerLabel,
                                javax.swing.GroupLayout.PREFERRED_SIZE, 493,
                                javax.swing.GroupLayout.PREFERRED_SIZE)))
            .addContainerGap()));

    layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {
        exitButton, launchButton });

    layout.setVerticalGroup(layout
        .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(
            javax.swing.GroupLayout.Alignment.TRAILING,
            layout
                .createSequentialGroup()
                .addContainerGap()
                .addGroup(
                    layout
                        .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(disclaimerLabel,
                            javax.swing.GroupLayout.PREFERRED_SIZE, 215,
                            javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(headingLabel,
                            javax.swing.GroupLayout.PREFERRED_SIZE, 116,
                            javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(58, 58, 58)
                .addGroup(
                    layout.createParallelGroup(javax.swing.GroupLayout.Alignment.CENTER)
                        .addComponent(browserButton).addComponent(exitButton))
                .addContainerGap())
        .addGroup(
            layout
                .createSequentialGroup()
                .addGap(259, 259, 259)
                .addGroup(
                    layout
                        .createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(launchButton,
                            javax.swing.GroupLayout.PREFERRED_SIZE, 50,
                            javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(statusLabel))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

    pack();
  }

  /**
   * This is the launch button action method. This method launches the Apache Sling
   * bootloader and informs the user to wait before accessing it in a browser.
   * 
   * @param evt
   *          The details of the Action event.
   * @throws IOException
   */
  private void launchButtonActionPerformed(java.awt.event.ActionEvent evt) {
    // Launch Nakamura
    if (runStatus == APP_NOT_RUNNING) {
      System.setSecurityManager(null);
      try {
        NakamuraMain.main(savedArgs);

        // Update label
        statusLabel.setText("Nakamura is starting...");

        // Notify the user
        JOptionPane.showMessageDialog(this,
            "Nakamura has been started.\nPlease allow 30-60 seconds for it to be ready.",
            "Information", JOptionPane.INFORMATION_MESSAGE);

        runStatus = APP_RUNNING;
        isStartupFinished();
      } catch (Exception e) {
        statusLabel.setText("Nakamura startup failed: " + e.getMessage());
        e.printStackTrace(System.err);
      }
    } else {
      // Can't start it again...
      // custom title, warning icon
      JOptionPane.showMessageDialog(this, "Nakamura is already running.", "Warning",
          JOptionPane.WARNING_MESSAGE);
    }
  }

  /**
   * Pings the Apache Sling server URL every 5 seconds to see if it has finished booting.
   * Once it receives an OK status, it enables the button to launch the browser and
   * disables the launch Nakamura button.
   */
  private void isStartupFinished() {
    boolean started = false;
    try {
      while (!started) {
        if (exists(localhostURL))
          started = true;
        Thread.sleep(5 * 1000);
      }
    } catch (InterruptedException e) {
      e.printStackTrace();
    }

    if (started) {
      statusLabel.setText("Nakamura is running.");
      statusLabel.setForeground(Color.green);
      launchButton.setEnabled(false);
      browserButton.setEnabled(true);
    }
  }

  /**
   * Pings the Apache Sling server URL, looking for an OK status. Returns true once that
   * OK status is received.
   * 
   * @param URLName
   *          The URL to ping.
   * @return true if OK status is received back. False if not OK.
   */
  public static boolean exists(String URLName) {
    try {
      HttpURLConnection.setFollowRedirects(false);
      // note : you may also need
      // HttpURLConnection.setInstanceFollowRedirects(false)
      HttpURLConnection con = (HttpURLConnection) new URL(URLName).openConnection();
      con.setRequestMethod("HEAD");
      return (con.getResponseCode() == HttpURLConnection.HTTP_OK);
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }

  /**
   * Performs the action when the exit button is pressed, which is exit the program.
   * 
   * @param evt
   *          The details of the event.
   */
  private void exitButtonActionPerformed(java.awt.event.ActionEvent evt) {
    // Kill Nakamura and the GUI app.
    System.exit(0);
  }

  /**
   * Performs the action when the browser button is pressed, which is launch a web browser
   * and browse to the server URL.
   * 
   * @param evt
   *          The details of the event.
   */
  private void browserButtonActionPerformed(java.awt.event.ActionEvent evt) {
    try {
      Desktop.getDesktop().browse(new URL(localhostURL).toURI());
    } catch (IOException e) {
      System.err.println("IO Exception: " + e.getMessage());
    } catch (URISyntaxException e) {
      System.err.println("URISyntaxException: " + e.getMessage());
    }
  }

  /**
   * Returns an ImageIcon, or null if the path was invalid.
   * 
   * @param path
   *          The path to the icon.
   * @param description
   *          The description of the icon.
   * @return the newly created ImageIcon or null.
   */
  protected ImageIcon createImageIcon(String path, String description) {
    java.net.URL imgURL = getClass().getResource(path);
    if (imgURL != null) {
      return new ImageIcon(imgURL, description);
    } else {
      System.err.println("Couldn't find file: " + path);
      return null;
    }
  }

  /**
   * Returns the full contents of a (assumed) text file for use in a label.
   * 
   * @param path
   *          The path to the text file.
   * @return The contents of the file as a String.
   * @throws IOException
   *           thrown if the file is unable to be read.
   */
  protected String getLabelText(String path) throws IOException {
    InputStream is = this.getClass().getResourceAsStream(path);
    if (is != null) {
      Writer writer = new StringWriter();

      char[] buffer = new char[1024];
      Reader reader = null;
      try {
        reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
        int n;
        while ((n = reader.read(buffer)) != -1) {
          writer.write(buffer, 0, n);
        }
      } finally {
        if (reader != null) {
          reader.close();
        }
        is.close();
      }
      return writer.toString();
    } else {
      System.err.println("Couldn't find file: " + path);
      return null;
    }
  }

  /**
   * The Main method which executes the program.
   * 
   * @param args
   *          the command line arguments
   */
  public static void main(String args[]) {
    savedArgs = args;
    java.awt.EventQueue.invokeLater(new Runnable() {

      public void run() {
        new LaunchNakamura().setVisible(true);
      }
    });
  }

  // Variables declaration - do not modify
  private javax.swing.JButton browserButton;
  private javax.swing.JLabel disclaimerLabel;
  private javax.swing.JButton exitButton;
  private javax.swing.JLabel headingLabel;
  private javax.swing.JButton launchButton;
  private javax.swing.JLabel statusLabel;
  // End of variables declaration

}
