import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import dbConnect from '@/lib/dbConnect';
import User from '@/models/User';
import bcrypt from 'bcryptjs';

const authSecret = process.env.NEXTAUTH_SECRET ||
  (process.env.NODE_ENV !== 'production' ? 'studysync-development-only-secret' : undefined);

const authOptions = {
  providers: [
    CredentialsProvider({
      name: 'credentials',
      credentials: {},
      async authorize(credentials) {
        const { email, password } = credentials;

        try {
          await dbConnect();
          const user = await User.findOne({ email }).select('+password');

          if (!user) {
            return null;
          }

          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (!passwordsMatch) {
            return null;
          }
          
          // Return user object without the role.
          return { id: user._id.toString(), email: user.email };
        } catch (error) {
          console.log('Error in authorize callback: ', error);
          return null;
        }
      },
    }),
  ],
  session: {
    strategy: 'jwt',
  },
  callbacks: {
    // JWT callback no longer needs to handle the role.
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
      }
      return token;
    },
    // Session callback no longer needs to handle the role.
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id;
      }
      return session;
    },
    // Keep redirects safe (same-origin). The login page controls the post-login redirect.
    async redirect({ url, baseUrl }) {
      return url.startsWith(baseUrl) ? url : baseUrl;
    },
  },
  pages: {
    signIn: '/login',
  },
  secret: authSecret,
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
